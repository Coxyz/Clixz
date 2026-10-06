"""Create a new service tree, ready to fill in.

Unlike v1, ``compose.yaml`` is not left empty and it is not generated from a
specification: it is written from a template that already carries the house
hardening, and it is yours to edit afterwards. The file says so in its first
line, so nobody has to guess whether editing it is allowed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import compose as compose_mod
from .archive import snapshot_file
from .config import Config
from .meta import SERVICE_FILENAME, scaffold_template
from .policy import COMPOSE, ENV_FILE, SERVICE_DIRS
from .system import CommandRunner, group_exists, user_exists

SERVICE_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


@dataclass(frozen=True)
class CreateRequest:
    category: str
    service: str
    # The files to write. None means the template: the hardened compose, the
    # commented service.yaml. A plan prepared through the MCP carries both.
    compose: str | None = None
    service_yaml: str | None = None


def validate_service_name(name: str) -> None:
    if not SERVICE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid service name '{name}' "
            "(lowercase letters, digits and hyphens; no leading or trailing hyphen)"
        )


def plan_create(config: Config, req: CreateRequest) -> list[list[str]]:
    """The commands ``create`` would run, without running them."""
    runner = CommandRunner(dry_run=True)
    _create(config, req, runner)
    return runner.executed


def create_service(
    config: Config, req: CreateRequest, *, dry_run: bool = False,
) -> list[list[str]]:
    runner = CommandRunner(dry_run=dry_run)
    _create(config, req, runner)
    return runner.executed


def _create(config: Config, req: CreateRequest, runner: CommandRunner) -> None:
    validate_service_name(req.service)
    cat = config.category(req.category)

    if not user_exists(cat.user):
        raise RuntimeError(f"System user '{cat.user}' does not exist. Create it first.")
    if not group_exists(cat.group):
        raise RuntimeError(f"System group '{cat.group}' does not exist. Create it first.")

    svc_path = config.root_dir / req.category / req.service
    if svc_path.exists():
        raise RuntimeError(f"Service path already exists: {svc_path}")

    dir_rule = config.rule("dir")
    file_rule = config.rule("file")
    env_rule = config.rule("env")

    def make_dir(path: Path) -> None:
        runner.run(["mkdir", "-p", str(path)])
        runner.run(["chown", dir_rule.owner or cat.owner, str(path)])
        runner.run(["chmod", dir_rule.mode, str(path)])

    def make_file(path: Path, content: str, owner: str, mode: str) -> None:
        runner.write_file(path, content)
        runner.run(["chown", owner, str(path)])
        runner.run(["chmod", mode, str(path)])

    make_dir(config.root_dir / req.category)
    make_dir(svc_path)
    for name in SERVICE_DIRS:
        make_dir(svc_path / name)

    make_file(
        svc_path / COMPOSE,
        req.compose if req.compose is not None
        else compose_mod.template(config, req.category, req.service),
        file_rule.owner or cat.owner, file_rule.mode,
    )
    make_file(
        svc_path / SERVICE_FILENAME,
        req.service_yaml if req.service_yaml is not None
        else scaffold_template(req.category, req.service),
        file_rule.owner or cat.owner, file_rule.mode,
    )
    make_file(
        svc_path / ENV_FILE,
        f"# {req.category}/{req.service} — secrets. Never committed, never in service.yaml.\n",
        env_rule.owner or cat.owner, env_rule.mode,
    )


def edit_service(
    config: Config, category: str, service: str, *, compose: str | None,
    service_yaml: str | None, dry_run: bool = False,
) -> list[list[str]]:
    """Replace ``compose.yaml`` and/or ``service.yaml``; return the commands.

    The previous version of each replaced file is copied under
    ``.archive/<category>/<service>/updates/`` first — nothing is ever lost to
    an edit. ``.env`` is not editable here: Komodo owns its contents.
    """
    cat = config.category(category)
    svc_path = config.root_dir / category / service
    if not svc_path.is_dir():
        raise RuntimeError(f"No such service: {category}/{service}")
    # Written as root: through a link, the write would land on its target.
    for path in (svc_path, svc_path / COMPOSE, svc_path / SERVICE_FILENAME):
        if path.is_symlink():
            raise RuntimeError(f"{path} is a symlink — refusing to write through it")

    file_rule = config.rule("file")
    runner = CommandRunner(dry_run=dry_run)
    commands: list[list[str]] = []
    for name, content in ((COMPOSE, compose), (SERVICE_FILENAME, service_yaml)):
        if content is None:
            continue
        path = svc_path / name
        if path.exists():
            snapshot = snapshot_file(config, category, service, path, dry_run=dry_run)
            commands += [["mkdir", "-p", str(snapshot.parent)],
                         ["cp", "-p", str(path), str(snapshot)]]
        done = len(runner.executed)
        runner.write_file(path, content)
        runner.run(["chown", file_rule.owner or cat.owner, str(path)])
        runner.run(["chmod", file_rule.mode, str(path)])
        commands += runner.executed[done:]
    return commands

