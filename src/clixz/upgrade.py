"""``clixz upgrade``: upgrade clixz with whichever installer put it here.

This exists because of the umask. A hardened host sets ``UMASK 027`` in
``/etc/login.defs``, and pipx and uv create their virtualenv with the process
defaults: a plain ``sudo pipx upgrade --global clixz`` leaves the environment
readable by root only, and the next ``clixz`` — or ``clixz-mcpd``, which runs
unprivileged — dies on "permission denied". System packages do not have the
problem because dpkg applies the modes recorded in the archive; a Python
installer has nothing recorded to apply.

So the upgrade goes through here, which sets the umask and runs the installer.
One command to remember instead of a wrapper script to forget.

It also restarts ``clixz-mcpd`` when the version changed. The daemon is a
long-running Python process: it keeps serving the code it imported at start,
and an upgrade that leaves it running has upgraded the CLI and not the gateway.
"""

from __future__ import annotations

import os
import shutil
import subprocess
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


MCPD_UNIT = "clixz-mcpd.service"
# try-restart, not restart: a daemon the operator stopped stays stopped.
RESTART_MCPD = ["systemctl", "try-restart", MCPD_UNIT]


def installed_version(python: str) -> str | None:
    """The version now on disk, asked of a fresh interpreter.

    This process imported the old code before the installer replaced it, so its
    own ``__version__`` cannot tell whether anything changed.
    """
    try:
        done = subprocess.run(
            [python, "-c", "import clixz; print(clixz.__version__)"],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None


def mcpd_running() -> bool:
    """True when the gateway is up — and therefore still running the old code."""
    if shutil.which("systemctl") is None:
        return False
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", MCPD_UNIT],
                              timeout=15, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
