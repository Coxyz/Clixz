"""Low-level filesystem primitives: modes, ownership, and command execution.

Configuration-agnostic on purpose — every policy decision lives in
``policy.py``. The only trace of POSIX ACLs left here is detection: v1 wrote
named ACL entries across the whole tree, so v2 has to *see* them in order to
strip them. It never writes one.
"""

from __future__ import annotations

import grp
import pwd
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

REQUIRED_BINS = ("chmod", "chown")


@dataclass(frozen=True)
class CommandExecutionError(RuntimeError):
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{' '.join(self.command)} exited {self.returncode}: {self.stderr.strip()}"


def missing_bins() -> list[str]:
    return [b for b in REQUIRED_BINS if shutil.which(b) is None]


# ─── user / group lookup ─────────────────────────────────────────────────────

def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def owner_ids(owner: str) -> tuple[int, int] | None:
    """Resolve ``"user:group"`` to ``(uid, gid)``, or None if either is unknown."""
    user, _, group = owner.partition(":")
    try:
        return pwd.getpwnam(user).pw_uid, grp.getgrnam(group or user).gr_gid
    except KeyError:
        return None


def _uid_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _gid_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


# ─── observed state ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PathState:
    path: Path
    exists: bool
    is_dir: bool
    mode: str          # octal, three digits
    owner: str         # "user:group", names where they resolve
    extended_acl: bool  # a v1 leftover: named ACL entries beyond the base mode


def read_state(path: Path) -> PathState:
    if not path.exists():
        return PathState(path, False, False, "000", "", False)
    st = path.stat()
    return PathState(
        path=path,
        exists=True,
        is_dir=stat.S_ISDIR(st.st_mode),
        mode=oct(st.st_mode & 0o7777)[2:].zfill(3)[-3:],
        owner=f"{_uid_name(st.st_uid)}:{_gid_name(st.st_gid)}",
        extended_acl=has_extended_acl(path),
    )


def has_extended_acl(path: Path) -> bool:
    """True if the path carries named ACL entries or a default ACL.

    v2 expects none anywhere. A path that still has them was configured by v1
    and needs ``setfacl -b``; `clixz check` reports it and `clixz fix` clears it.
    Returns False when getfacl is unavailable — a missing tool is not evidence
    of drift, and reporting it as such would produce noise on every path.
    """
    try:
        out = subprocess.run(
            ["getfacl", "-pcE", str(path)],
            check=True, capture_output=True, text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("default:"):
            return True
        tag, _, rest = line.partition(":")
        qualifier, _, _ = rest.partition(":")
        if tag in ("user", "group") and qualifier:
            return True
    return False


# ─── execution ───────────────────────────────────────────────────────────────

class CommandRunner:
    """Runs commands, recording each one. ``dry_run`` records without running."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.executed: list[list[str]] = []

    def run(self, command: list[str]) -> None:
        self.executed.append(command)
        if self.dry_run:
            return
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            raise CommandExecutionError(
                command=tuple(command), returncode=exc.returncode,
                stdout=exc.stdout or "", stderr=exc.stderr or "",
            ) from exc

    def write_file(self, path: Path, content: str) -> None:
        if not self.dry_run:
            path.write_text(content, encoding="utf-8")
        self.executed.append(["write_file", str(path)])
