"""``clixz upgrade``: upgrade clixz with whichever installer put it here.

This exists because of the umask. A hardened host sets ``UMASK 027`` in
``/etc/login.defs``, and pipx and uv create their virtualenv with the process
defaults: a plain ``sudo pipx upgrade --global clixz`` leaves the environment
readable by root only, and the next ``clixz`` — or ``clixz-mcpd``, which runs
unprivileged — dies on "permission denied". System packages do not have the
problem because dpkg applies the modes recorded in the archive; a Python
installer has nothing recorded to apply.

So the upgrade goes through here, which sets the umask and hands over to the
installer. One command to remember instead of a wrapper script to forget.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE = "clixz"
# World-readable, owner-writable: what an installed tool is expected to be.
UMASK = 0o022
# Where `pipx --global` keeps its environments unless PIPX_GLOBAL_HOME says otherwise.
PIPX_GLOBAL_HOME = Path("/opt/pipx")


@dataclass(frozen=True)
class UpgradePlan:
    installer: str
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)


def plan_upgrade(prefix: Path, launcher: Path | None = None,
                 environ: dict[str, str] | None = None) -> UpgradePlan | None:
    """The command that upgrades the install living in ``prefix``, if we know one.

    ``prefix`` is the virtualenv clixz runs from; ``launcher`` is the path the
    user typed (``/usr/local/bin/clixz``), which is where uv put its link.
    """
    environ = os.environ if environ is None else environ
    if (prefix / "pipx_metadata.json").is_file():
        home = Path(environ.get("PIPX_GLOBAL_HOME") or PIPX_GLOBAL_HOME)
        argv = ["pipx", "upgrade"]
        if home in prefix.parents:
            argv.append("--global")
        return UpgradePlan("pipx", [*argv, PACKAGE])
    if (prefix / "uv-receipt.toml").is_file():
        # uv has no system-wide switch: it finds a tool only if pointed at the
        # directory it was installed in, and relinks into the same bin dir.
        env = {"UV_TOOL_DIR": str(prefix.parent)}
        if launcher is not None and launcher.is_symlink():
            env["UV_TOOL_BIN_DIR"] = str(launcher.parent)
        return UpgradePlan("uv", ["uv", "tool", "upgrade", PACKAGE], env)
    return None


def needs_root(prefix: Path) -> bool:
    return not os.access(prefix, os.W_OK)
