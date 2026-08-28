"""Archive services and file snapshots instead of deleting them.

The rule this module exists to enforce: **nothing is ever destroyed**. Removing
a service moves its tree under the archive root; overwriting an editable file
first snapshots the previous content there. Real deletion stays possible, but
only through an explicit ``--force`` reserved for a human operator — never
reachable from an automated caller.

Layout under ``<root_dir>/.archive/`` ::

    .archive/<category>/<service>/<UTC timestamp>/          full service tree
    .archive/<category>/<service>/updates/<ts>-<filename>   pre-update snapshots

``.archive`` starts with a dot and is not a configured category, so the
discovery walk never sees it: archived services disappear from ``list`` and
``check`` without needing an exclusion rule.

The archive root is ``755 root:root``: owned by root so nothing but the daemon
writes there, but readable so an operator can see what was archived without
sudo. Secrets are not exposed by this — ``mv`` preserves permissions, so an
archived ``.env`` keeps its own ``600 root:root``. Locking the root down to
``700`` as well was redundant belt-and-braces that mostly got in the way.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import Config
from .system import CommandRunner

ARCHIVE_DIRNAME = ".archive"
ARCHIVE_MODE = "755"
ARCHIVE_OWNER = "root:root"


@dataclass
class ArchiveResult:
    source: Path
    destination: Path | None
    commands: list[list[str]]
    forced: bool = False


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def archive_root(config: Config) -> Path:
    return config.root_dir / ARCHIVE_DIRNAME


def _secure_root(runner: CommandRunner, config: Config) -> None:
    """Give the archive root to root, readable by everyone else.

    Root ownership is what matters: only the privileged daemon adds to the
    archive. Readability is deliberate — an operator should be able to see what
    was archived without sudo, and the archived files keep their own modes, so
    a ``.env`` in there is still ``600 root:root``.

    ``chown`` is skipped when unprivileged: the mutating commands run as root in
    practice, and refusing to snapshot just because the caller cannot chown
    would trade a real safety net for a cosmetic guarantee.
    """
    root = archive_root(config)
    if os.geteuid() == 0:
        runner.run(["chown", "-R", ARCHIVE_OWNER, str(root)])
    runner.run(["chmod", ARCHIVE_MODE, str(root)])


def snapshot_file(
    config: Config, category: str, service: str, path: Path, *, dry_run: bool
) -> Path:
    """Copy ``path`` into the service's archive area before it gets overwritten."""
    dest_dir = archive_root(config) / category / service / "updates"
    dest = dest_dir / f"{_timestamp()}-{path.name}"
    runner = CommandRunner(dry_run=dry_run)
    runner.run(["mkdir", "-p", str(dest_dir)])
    runner.run(["cp", "-p", str(path), str(dest)])
    _secure_root(runner, config)
    return dest


def archive_service(
    config: Config,
    category: str,
    service: str,
    *,
    dry_run: bool,
    force: bool = False,
) -> ArchiveResult:
    """Move a service tree into the archive, or delete it outright when forced.

    ``force`` is the only destructive path in this CLI. It is never exposed to
    automated callers — see the ``archive`` command and the MCP server.
    """
    svc_path = config.root_dir / category / service
    if not svc_path.is_dir():
        raise RuntimeError(f"No such service: {category}/{service}")

    # A symlinked service directory would otherwise move (or delete) whatever it
    # points at, anywhere on the host.
    resolved = svc_path.resolve()
    expected = (config.root_dir / category).resolve() / service
    if resolved != expected:
        raise RuntimeError(f"{svc_path} resolves outside the root dir — refusing to touch it.")

    runner = CommandRunner(dry_run=dry_run)

    if force:
        runner.run(["rm", "-rf", str(svc_path)])
        return ArchiveResult(source=svc_path, destination=None,
                             commands=runner.executed, forced=True)

    dest_dir = archive_root(config) / category / service
    dest = dest_dir / _timestamp()
    runner.run(["mkdir", "-p", str(dest_dir)])
    runner.run(["mv", str(svc_path), str(dest)])
    _secure_root(runner, config)
    return ArchiveResult(source=svc_path, destination=dest, commands=runner.executed)


def list_archived(config: Config) -> list[tuple[str, str, str, Path]]:
    """Archived service trees as ``(category, service, timestamp, path)``."""
    root = archive_root(config)
    if not root.is_dir():
        return []
    out: list[tuple[str, str, str, Path]] = []
    for cat_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for svc_dir in sorted(p for p in cat_dir.iterdir() if p.is_dir()):
            for stamp in sorted((p for p in svc_dir.iterdir() if p.is_dir()), reverse=True):
                if stamp.name == "updates":
                    continue
                out.append((cat_dir.name, svc_dir.name, stamp.name, stamp))
    return out
