"""The to-do list shared by the operator and the AI.

Not a log of what was done: a list of what is left to do. Each item has a
title, a description and a state — ``todo``, ``doing``, ``done``, ``archived``.
The CLI (``clixz todo``) and the MCP server read and write the same file, with
the same rights.

The file is not sensitive, so it is readable by everyone and writable by the
operators' group: editing it must never need sudo. Writes happen in place
under an exclusive ``flock`` — no temporary file and rename — so the owner and
the mode survive whoever wrote last, and two writers never lose each other's
change. Root (``clixz-apply``, writing for the AI) also puts the group and the
mode back, so a file someone created by hand converges to the rule.
"""

from __future__ import annotations

import fcntl
import grp
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import yaml

STATES = ("todo", "doing", "done", "archived")
OPEN_STATES = ("todo", "doing")
TITLE_MAX = 200
DESCRIPTION_MAX = 20_000
FILE_MODE = 0o664
HEADER = ("# clixz todo — what is left to do. Edit it with `clixz todo`, or by hand.\n"
          "# Readable by everyone; the AI reads and writes it through the MCP server.\n")


class TodoError(ValueError):
    """A request the list cannot honour. The message is caller-facing."""


@dataclass
class Item:
    id: int
    title: str
    state: str
    created: str
    updated: str
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _title(value: object) -> str:
    if not isinstance(value, str):
        raise TodoError("the title must be a string")
    title = value.strip()
    if not title:
        raise TodoError("the title is empty")
    if "\n" in title or "\r" in title:
        raise TodoError("the title must fit on one line — put the rest in the description")
    if len(title) > TITLE_MAX:
        raise TodoError(f"the title is longer than {TITLE_MAX} characters")
    return title


def _description(value: object) -> str:
    if not isinstance(value, str):
        raise TodoError("the description must be a string")
    if len(value) > DESCRIPTION_MAX:
        raise TodoError(f"the description is longer than {DESCRIPTION_MAX} characters")
    return value.strip("\n")


def _state(value: object) -> str:
    if value not in STATES:
        raise TodoError(f"unknown state {value!r} (known: {', '.join(STATES)})")
    return str(value)


class _Dumper(yaml.SafeDumper):
    """Multi-line descriptions as ``|`` blocks, so the file stays readable."""


def _represent_str(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    if "\n" in value:
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", value)


_Dumper.add_representer(str, _represent_str)


class TodoStore:
    def __init__(self, path: Path, group: str | None = None) -> None:
        self.path = path
        self.group = group

    # ─── reading ─────────────────────────────────────────────────────────────

    def _parse(self, text: str) -> tuple[list[Item], int]:
        try:
            raw = yaml.safe_load(text) if text.strip() else None
        except yaml.YAMLError as exc:
            raise TodoError(f"{self.path} is not valid YAML — fix it by hand: {exc}") from exc
        if raw is None:
            return [], 1
        if not isinstance(raw, dict) or not isinstance(raw.get("items", []), list):
            raise TodoError(f"{self.path} must be a mapping with an 'items' list")
        items: list[Item] = []
        for entry in raw.get("items") or []:
            try:
                items.append(Item(
                    id=int(entry["id"]), title=str(entry["title"]), state=_state(entry["state"]),
                    created=str(entry.get("created", "")), updated=str(entry.get("updated", "")),
                    description=str(entry.get("description") or ""),
                ))
            except (KeyError, TypeError, ValueError) as exc:
                raise TodoError(f"{self.path}: unreadable item {entry!r}: {exc}") from exc
        highest = max((i.id for i in items), default=0)
        try:
            next_id = max(int(raw.get("next_id") or 1), highest + 1)
        except (TypeError, ValueError):
            next_id = highest + 1
        return sorted(items, key=lambda i: i.id), next_id

    def items(self) -> list[Item]:
        try:
            with self.path.open("r", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                return self._parse(f.read())[0]
        except FileNotFoundError:
            return []

    def get(self, item_id: int) -> Item:
        for item in self.items():
            if item.id == item_id:
                return item
        raise TodoError(f"no item #{item_id}")

    # ─── writing ─────────────────────────────────────────────────────────────

    def _dump(self, items: list[Item], next_id: int) -> str:
        body = {"next_id": next_id, "items": [i.to_dict() for i in items]}
        return HEADER + yaml.dump(body, Dumper=_Dumper, sort_keys=False, allow_unicode=True,
                                  width=100)

    def _enforce_permissions(self, fd: int, created: bool) -> None:
        if os.geteuid() == 0:
            gid = -1
            if self.group:
                try:
                    gid = grp.getgrnam(self.group).gr_gid
                except KeyError:
                    pass
            os.fchown(fd, 0, gid)
            os.fchmod(fd, FILE_MODE)
        elif created:
            # Ours: the umask may have taken the group's write bit away.
            os.fchmod(fd, FILE_MODE)

    @contextmanager
    def _transaction(self) -> Iterator[tuple[list[Item], list[int]]]:
        """Yield ``(items, [next_id])`` locked; write them back on success."""
        created = not self.path.exists()
        if created:
            # `clixz daemon install` makes it root:<group> 2775; before that,
            # a first write still has to land somewhere.
            self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, FILE_MODE)
        with os.fdopen(fd, "r+", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            items, next_id = self._parse(f.read())
            counter = [next_id]
            yield items, counter
            text = self._dump(sorted(items, key=lambda i: i.id), counter[0])
            f.seek(0)
            f.truncate()
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            self._enforce_permissions(f.fileno(), created)

    def add(self, title: str, description: str = "", state: str = "todo") -> Item:
        title, description, state = _title(title), _description(description), _state(state)
        with self._transaction() as (items, counter):
            now = _now()
            item = Item(id=counter[0], title=title, state=state, created=now, updated=now,
                        description=description)
            items.append(item)
            counter[0] += 1
        return item

    def update(self, item_id: int, *, title: str | None = None,
               description: str | None = None, state: str | None = None) -> Item:
        new_title = _title(title) if title is not None else None
        new_description = _description(description) if description is not None else None
        new_state = _state(state) if state is not None else None
        with self._transaction() as (items, _):
            for item in items:
                if item.id == item_id:
                    break
            else:
                raise TodoError(f"no item #{item_id}")
            if new_title is not None:
                item.title = new_title
            if new_description is not None:
                item.description = new_description
            if new_state is not None:
                item.state = new_state
            item.updated = _now()
        return item

    def remove(self, item_id: int) -> Item:
        with self._transaction() as (items, _):
            for index, item in enumerate(items):
                if item.id == item_id:
                    return items.pop(index)
            raise TodoError(f"no item #{item_id}")
