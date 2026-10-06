"""The package installs and keeps its own systemd units.

Until 2.3 the units lived in the repository's ``deploy/`` and were copied by
hand; the copies drifted (a category's group added to one and not the other,
then forgotten for the next category). Now they ship in the package as
templates, ``clixz daemon install`` renders them from the config — the
gateway's groups are the categories' — and writes the ones that changed, and
``clixz upgrade`` runs it from the new version.

Three units:

- ``clixz-mcpd.service``: the unprivileged gateway the MCP container talks to;
- ``clixz-apply.socket`` and ``clixz-apply@.service``: the root half, one
  process per request, reachable from the gateway only.

Starting is only ever done for a unit that was not installed before: an
operator who stopped the gateway does not see an upgrade start it again.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from importlib.resources import files
from pathlib import Path

from . import __file__ as _package_init
from .config import DEFAULT_CONFIG_DIR, Config
from .system import CommandRunner, group_exists, user_exists
from .todo import HEADER as TODO_HEADER

UNIT_DIR = Path("/etc/systemd/system")
MCPD_UNIT = "clixz-mcpd.service"
APPLY_SOCKET_UNIT = "clixz-apply.socket"
APPLY_SERVICE_UNIT = "clixz-apply@.service"
UNITS = (MCPD_UNIT, APPLY_SOCKET_UNIT, APPLY_SERVICE_UNIT)
# The units an install enables: the template service is started by the socket.
ENABLED = (MCPD_UNIT, APPLY_SOCKET_UNIT)
# Units of earlier versions, removed when found.
RETIRED_UNITS = ("clixz-snapshot.timer", "clixz-snapshot.service",
                 "clixz-admind.service", "clixz-runnerd.service")
ACCOUNT = "svc_mcprun"
# try-restart, not restart: a daemon the operator stopped stays stopped.
RESTART_MCPD = ["systemctl", "try-restart", MCPD_UNIT]
RESTART_APPLY_SOCKET = ["systemctl", "try-restart", APPLY_SOCKET_UNIT]


def render_units(config: Config) -> dict[str, str]:
    """Each unit's text, rendered from the package template and the config."""
    substitutions = {
        "@GROUPS@": " ".join(sorted({c.group for c in config.categories.values()})),
        "@ROOT_DIR@": str(config.root_dir),
        "@CONFIG_DIR@": str(config.config_dir or DEFAULT_CONFIG_DIR),
        "@STATE_DIR@": str(config.state.dir),
        "@MANIFEST@": str(config.resolved_manifest_path),
    }
    out = {}
    for name in UNITS:
        text = files("clixz").joinpath("systemd", name).read_text(encoding="utf-8")
        for placeholder, value in substitutions.items():
            text = text.replace(placeholder, value)
        out[name] = text
    return out


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def unit_drift(config: Config, unit_dir: Path = UNIT_DIR) -> dict[str, str]:
    """``{unit: "ok" | "missing" | "differs"}`` against what the package renders."""
    out = {}
    for name, text in render_units(config).items():
        current = _read(unit_dir / name)
        out[name] = "missing" if current is None else ("ok" if current == text else "differs")
    return out


def _systemctl(*args: str) -> str:
    if shutil.which("systemctl") is None:
        return ""
    try:
        return subprocess.run(["systemctl", *args], capture_output=True, text=True,
                              timeout=15, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def is_active(unit: str) -> bool:
    return _systemctl("is-active", unit) == "active"


def mcpd_stale() -> bool | None:
    """True when the running gateway started before this clixz was installed.

    It then serves the code it imported at start. None when it is not running
    or systemd cannot tell. (The gateway also notices on its own within 30 s;
    this is for an install that wants it done now.)
    """
    started = _systemctl("show", "-p", "ExecMainStartTimestampMonotonic", "--value", MCPD_UNIT)
    if not started.isdigit() or started == "0" or not is_active(MCPD_UNIT):
        return None
    started_at = time.time() - (time.monotonic() - int(started) / 1_000_000)
    return started_at < Path(_package_init).stat().st_mtime


def install(config: Config, *, unit_dir: Path = UNIT_DIR, dry_run: bool = False) -> list[list[str]]:
    """Put the host in the state the package describes; return what was run."""
    runner = CommandRunner(dry_run=dry_run)
    drift = unit_drift(config, unit_dir)

    if not user_exists(ACCOUNT):
        runner.run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin",
                    ACCOUNT])

    state = config.state
    group = state.group if group_exists(state.group) else "root"
    runner.run(["mkdir", "-p", str(state.plans_dir)])
    runner.run(["chown", f"root:{group}", str(state.dir)])
    runner.run(["chmod", "2775", str(state.dir)])
    runner.run(["chown", "root:root", str(state.plans_dir)])
    runner.run(["chmod", "700", str(state.plans_dir)])
    if not state.todo_file.exists():
        runner.write_file(state.todo_file, TODO_HEADER)
    runner.run(["chown", f"root:{group}", str(state.todo_file)])
    runner.run(["chmod", "664", str(state.todo_file)])

    # clixz-apply's sandbox makes this one file writable, and systemd can only
    # do that for a path that exists.
    manifest = config.resolved_manifest_path
    if not manifest.exists():
        runner.run(["mkdir", "-p", str(manifest.parent)])
        runner.write_file(manifest, '{"schema": 1, "services": []}\n')
        runner.run(["chmod", "644", str(manifest)])

    reload_needed = False
    for name in RETIRED_UNITS:
        if (unit_dir / name).exists():
            runner.run(["systemctl", "disable", "--now", name])
            runner.run(["rm", "-f", str(unit_dir / name)])
            reload_needed = True
    snapshot = (config.config_dir or DEFAULT_CONFIG_DIR) / "npm-hosts.json"
    if snapshot.exists():
        runner.run(["rm", "-f", str(snapshot)])

    for name, text in render_units(config).items():
        if drift[name] != "ok":
            path = unit_dir / name
            runner.write_file(path, text)
            runner.run(["chmod", "644", str(path)])
            reload_needed = True
    if reload_needed:
        runner.run(["systemctl", "daemon-reload"])

    new = [name for name in ENABLED if drift[name] == "missing"]
    if new:
        runner.run(["systemctl", "enable", "--now", *new])
    if drift[MCPD_UNIT] == "differs" or (drift[MCPD_UNIT] == "ok" and mcpd_stale()):
        runner.run(RESTART_MCPD)
    if drift[APPLY_SOCKET_UNIT] == "differs":
        runner.run(RESTART_APPLY_SOCKET)
    return runner.executed


def status(config: Config, unit_dir: Path = UNIT_DIR) -> dict:
    """What `clixz daemon status` shows. Needs no privilege."""
    drift = unit_drift(config, unit_dir)
    return {
        "units": [{"name": name, "file": str(unit_dir / name), "state": drift[name],
                   "active": is_active(name) if name in ENABLED else None}
                  for name in UNITS],
        "retired_present": [name for name in RETIRED_UNITS if (unit_dir / name).exists()],
        "mcpd_stale": mcpd_stale(),
        "apply_socket": os.path.exists("/run/clixz-apply.sock"),
        "state_dir": str(config.state.dir),
        "state_dir_present": config.state.dir.is_dir(),
    }
