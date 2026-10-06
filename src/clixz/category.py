"""``clixz category add``: a new category, with the account that owns it.

A category is three things that must agree: a system account, a directory owned
by it, and an entry in ``config.yaml``. Doing them by hand means doing them in
the right order and remembering the third; this does all three, and says what
is left — the two places that list the category groups so the MCP side can read
the new tree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import Config
from .system import CommandRunner, group_exists, user_exists

# A directory name under root_dir and the stem of an account name.
CATEGORY_NAME_RE = re.compile(r"^[a-z]([a-z0-9-]*[a-z0-9])?$")
ACCOUNT_NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")


@dataclass
class CategoryPlan:
    commands: list[list[str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def default_account(name: str) -> str:
    return f"svc_{name.replace('-', '_')}"


def insert_category(text: str, name: str, user: str, group: str) -> str:
    """Add one entry to the ``categories:`` block of a config, as text.

    Text and not a YAML round trip: dumping the parsed document would drop every
    comment in a file whose comments are most of its value.
    """
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines)
                     if re.match(r"^categories:\s*(#.*)?$", line))
    except StopIteration:
        raise ValueError("no block-style 'categories:' section to add to") from None

    last, indent = None, None
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.strip() and not line[0].isspace():
            break  # the next top-level key
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indent is None:
            indent = line[: len(line) - len(line.lstrip())]
        last = i
    if last is None or indent is None:
        raise ValueError("'categories:' is empty — add the first entry by hand")

    lines.insert(last + 1, f"{indent}{name}: {{ user: {user}, group: {group} }}")
    result = "\n".join(lines) + ("\n" if text.endswith("\n") else "")

    # Never trust a text edit of YAML without reading it back.
    parsed = yaml.safe_load(result)
    if (parsed or {}).get("categories", {}).get(name) != {"user": user, "group": group}:
        raise ValueError("could not add the category without breaking the file — "
                         "edit it with `clixz config --edit`")
    return result


def _build(config: Config, source: Path | None, name: str, account: str | None,
           runner: CommandRunner) -> CategoryPlan:
    if not CATEGORY_NAME_RE.match(name):
        raise ValueError(
            f"Invalid category name '{name}' "
            "(lowercase letters, digits and hyphens; starts with a letter)"
        )
    if name in config.categories:
        raise ValueError(f"Category '{name}' already exists.")
    if source is None:
        raise ValueError("No config file to add the category to — create one with "
                         "`clixz config --edit` first.")
    account = account or default_account(name)
    if not ACCOUNT_NAME_RE.match(account):
        raise ValueError(f"Invalid account name '{account}'.")

    new_text = insert_category(source.read_text(encoding="utf-8"), name, account, account)

    if not group_exists(account):
        runner.run(["groupadd", "--system", account])
    if not user_exists(account):
        runner.run(["useradd", "--system", "--gid", account, "--no-create-home",
                    "--shell", "/usr/sbin/nologin", account])

    rule = config.rule("dir")
    path = config.root_dir / name
    runner.run(["mkdir", "-p", str(path)])
    runner.run(["chown", rule.owner or f"{account}:{account}", str(path)])
    runner.run(["chmod", rule.mode, str(path)])
    # Last, so a failure above leaves the config describing what exists.
    runner.write_file(source, new_text)

    plan = CategoryPlan(commands=runner.executed)
    plan.notes = [
        f"clixz-mcpd reads the tree through its groups: `sudo clixz daemon install` "
        f"adds {account} to them and restarts it.",
        f"The MCP container does the same: add the GID of group {account} "
        f"(`getent group {account}` — not the user's UID, `id -u {account}`) "
        "to group_add in its compose.yaml and redeploy it.",
    ]
    return plan


def plan_add(config: Config, source: Path | None, name: str,
             account: str | None = None) -> CategoryPlan:
    return _build(config, source, name, account, CommandRunner(dry_run=True))


def add_category(config: Config, source: Path | None, name: str,
                 account: str | None = None) -> CategoryPlan:
    return _build(config, source, name, account, CommandRunner())
