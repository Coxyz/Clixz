"""Backward compatibility with the previous name of this tool (``coxyz``).

The rename is cosmetic, but the world it runs in is not: there is a live
``/etc/coxyz/config.yaml`` on the host, systemd units carrying ``COXYZ_*``
variables, and an MCP container whose environment is stored in Komodo. Renaming
without a fallback would take the whole thing down at the next redeploy, for no
benefit.

So both spellings are accepted, with the new one winning. The legacy names are
read, never written: nothing here creates a ``coxyz`` path or exports a
``COXYZ_*`` variable. They can be dropped once the host has been migrated —
:func:`legacy_config_in_use` exists to tell you when that is safe.
"""

from __future__ import annotations

import os
from pathlib import Path

LEGACY_NAME = "coxyz"
NAME = "clixz"


def env(suffix: str, default: str = "") -> str:
    """Read ``CLIXZ_<suffix>``, falling back to the legacy ``COXYZ_<suffix>``.

    An empty value counts as unset: systemd writes ``Environment=CLIXZ_X=`` for
    an option left blank, and that should not shadow a legacy value.
    """
    value = os.environ.get(f"CLIXZ_{suffix}", "").strip()
    if value:
        return value
    return os.environ.get(f"COXYZ_{suffix}", "").strip() or default


def config_locations() -> tuple[Path, ...]:
    """Where to look for config.yaml, new locations first."""
    home = Path.home()
    return (
        Path(f"/etc/{NAME}/config.yaml"),
        home / ".config" / NAME / "config.yaml",
        Path(f"/etc/{LEGACY_NAME}/config.yaml"),
        home / ".config" / LEGACY_NAME / "config.yaml",
    )


def legacy_config_in_use() -> Path | None:
    """The legacy config path in use, when no current one exists.

    Lets the CLI tell the operator to migrate instead of silently depending on
    a path named after a tool that no longer exists.
    """
    for path in config_locations():
        if path.is_file():
            return path if LEGACY_NAME in path.parts else None
    return None
