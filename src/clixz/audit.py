"""The audit log: a trace of every action that changes something.

Since 2.3 changes come from two places — the operator at the CLI, and the AI
through the MCP server and ``clixz-apply`` — and a change nobody can trace is a
change nobody can explain. Every action that writes (a service created, edited,
fixed or archived, a plan stored, applied or dropped, a todo item, a category,
a repo, the config, the units, an upgrade) leaves one JSON line in
``<state>/audit.log``, whether it succeeded or failed. Reads leave nothing.

Two copies:

- ``audit.log``, next to the plans and the todo: readable by everyone (it holds
  no secret — paths, names, commands) and appendable by the operators' group,
  so that the actions they run without sudo are traced too. ``clixz log``
  reads it, and the MCP server through it;
- the systemd journal, under the identifier ``clixz`` (``journalctl -t
  clixz``), which only root can alter.

Logging never breaks the action it records: a log that cannot be written is
reported on stderr, and the action goes on.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config

LOG_NAME = "audit.log"
MAX_BYTES = 5 * 1024 * 1024
MAX_COMMANDS = 200
FILE_MODE = 0o664
JOURNAL_IDENT = "clixz"


def log_path(config: Config) -> Path:
    return config.state.dir / LOG_NAME


def current_actor() -> str:
    """The person behind the action: the sudo caller rather than root."""
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        return os.environ["SUDO_USER"]
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return str(os.getuid())


def _journal(message: str) -> None:
    try:
        import syslog

        syslog.openlog(JOURNAL_IDENT, syslog.LOG_PID, syslog.LOG_USER)
        syslog.syslog(syslog.LOG_NOTICE, message)
    except (ImportError, OSError):  # pragma: no cover - no syslog on this platform
        pass


def _rotate(path: Path) -> None:
    try:
        if path.stat().st_size >= MAX_BYTES:
            os.replace(path, path.with_name(LOG_NAME + ".1"))
    except FileNotFoundError:
        pass


def _append(config: Config, line: str) -> None:
    path = log_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    _rotate(path)
    created = not path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, FILE_MODE)
    try:
        if os.geteuid() == 0:
            try:
                os.fchown(fd, 0, grp.getgrnam(config.state.group).gr_gid)
            except KeyError:
                pass
            os.fchmod(fd, FILE_MODE)
        elif created:
            os.fchmod(fd, FILE_MODE)
        os.write(fd, (line + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def record(config: Config, source: str, action: str, target: str, *, ok: bool = True,
           plan_id: str | None = None, commands: list[list[str]] | None = None,
           error: str | None = None, notes: list[str] | None = None,
           actor: str | None = None) -> None:
    """Trace one action. ``source`` is ``cli`` or ``mcp``. Never raises."""
    commands = [list(map(str, c)) for c in (commands or [])]
    entry: dict[str, Any] = {
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "actor": actor or ("mcp" if source == "mcp" else current_actor()),
        "action": action,
        "target": target,
        "ok": ok,
        "plan_id": plan_id,
        "commands": commands[:MAX_COMMANDS],
        "error": error,
        "notes": list(notes or []),
    }
    if len(commands) > MAX_COMMANDS:
        entry["commands_total"] = len(commands)
    _journal(f"[{entry['source']}] {entry['actor']} {action} {target}"
             f"{' plan=' + plan_id if plan_id else ''} — {'ok' if ok else 'FAILED'}"
             f"{': ' + error if error else ''}"
             f"{f' ({len(commands)} command(s))' if commands else ''}")
    try:
        _append(config, json.dumps(entry, ensure_ascii=False))
    except OSError as exc:
        print(f"clixz: could not write the audit log {log_path(config)}: {exc}", file=sys.stderr)


def entries(config: Config, *, limit: int | None = None, action: str | None = None,
            target: str | None = None) -> list[dict]:
    """The recorded actions, newest first, optionally filtered."""
    path = log_path(config)
    out: list[dict] = []
    for source in (path, path.with_name(LOG_NAME + ".1")):
        try:
            lines = source.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, IsADirectoryError):
            continue
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            if action and entry.get("action") != action:
                continue
            if target and entry.get("target") != target:
                continue
            out.append(entry)
            if limit is not None and len(out) >= limit:
                return out
    return out
