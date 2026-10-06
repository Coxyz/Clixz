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

It installs **the version PyPI publishes now**, without any cache. Right after
a release, a plain ``pipx upgrade`` would often find nothing: pip's HTTP cache
still held the index from before. So the upgrade asks PyPI for the latest
version first, runs the installer with caching off, checks what landed, and
tries again a few times while the index propagates.

Then it runs ``clixz daemon install`` **from the new version**: the units the
new package ships are written, and ``clixz-mcpd`` — a long-running process that
keeps the code it imported — is restarted on the new code.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

PACKAGE = "clixz"
PYPI_URL = f"https://pypi.org/pypi/{PACKAGE}/json"
# How many times the installer runs while PyPI's index catches up with a
# release, and how long to wait in between.
RETRIES = 3
RETRY_DELAY = 15
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
        # Without the cache: a release minutes old is otherwise not seen.
        argv = ["pipx", "upgrade", "--pip-args=--no-cache-dir"]
        if home in prefix.parents:
            argv.append("--global")
        return UpgradePlan("pipx", [*argv, PACKAGE])
    if (prefix / "uv-receipt.toml").is_file():
        # uv has no system-wide switch: it finds a tool only if pointed at the
        # directory it was installed in, and relinks into the same bin dir.
        env = {"UV_TOOL_DIR": str(prefix.parent)}
        if launcher is not None and launcher.is_symlink():
            env["UV_TOOL_BIN_DIR"] = str(launcher.parent)
        return UpgradePlan("uv", ["uv", "tool", "upgrade", "--no-cache", PACKAGE], env)
    return None


def needs_root(prefix: Path) -> bool:
    return not os.access(prefix, os.W_OK)


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


def latest_version(opener: Callable[..., Any] = urllib.request.urlopen,
                   timeout: float = 10) -> str | None:
    """The version PyPI publishes now, or None when it cannot be asked."""
    request = urllib.request.Request(PYPI_URL, headers={"Cache-Control": "no-cache",
                                                        "Accept": "application/json"})
    try:
        with opener(request, timeout=timeout) as response:
            return str(json.loads(response.read().decode("utf-8"))["info"]["version"])
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError):
        return None


def run_upgrade(run: Callable[[], int], latest: str | None, *,
                version_after: Callable[[], str | None],
                sleep: Callable[[float], Any] = time.sleep,
                retries: int = RETRIES, delay: float = RETRY_DELAY) -> tuple[int, str | None]:
    """Run the installer until ``latest`` is what is installed.

    Returns ``(installer exit code, version installed)``. Without ``latest``
    (PyPI could not be asked) one run is all there is to do.
    """
    after: str | None = None
    for attempt in range(retries if latest else 1):
        code = run()
        if code != 0:
            return code, None
        after = version_after()
        if latest is None or after == latest:
            return 0, after
        if attempt + 1 < retries:
            sleep(delay)
    return 0, after
