"""Scaffold a new service directory tree.

``create`` only lays out the structure — the category/service directories,
``config/`` and ``data/``, plus empty ``compose.yaml`` and ``.env`` files — and
brings every path to its correct owner/mode/ACL. The operator fills in
``compose.yaml`` and ``.env`` afterwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .meta import SERVICE_FILENAME, scaffold_template
from .policy import plan_path
from .system import CommandRunner, group_exists, user_exists

SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$")


@dataclass(frozen=True)
class CreateRequest:
    category: str
    service: str


def validate_service_name(name: str) -> None:
    if not SERVICE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid service name '{name}' "
            "(alphanumeric and hyphens, no leading/trailing hyphen)"
        )


def create_service(
    config: Config,
    req: CreateRequest,
    *,
    dry_run: bool,
    acl_enabled: bool,
    principals_available: dict[str, bool],
) -> list[list[str]]:
    """Create the service tree. Returns the list of commands executed (or planned)."""
    validate_service_name(req.service)
    cat = config.category(req.category)

    if not user_exists(cat.user):
        raise RuntimeError(f"System user '{cat.user}' does not exist. Create it first.")
    if not group_exists(cat.group):
        raise RuntimeError(f"System group '{cat.group}' does not exist. Create it first.")

    svc_path = config.root_dir / req.category / req.service
    if svc_path.exists():
        raise RuntimeError(f"Service path already exists: {svc_path}")

    runner = CommandRunner(dry_run=dry_run)

    def apply_rule(path: Path, rule_name: str, *, is_dir: bool) -> None:
        rule = config.rule_or_default(rule_name)
        owner = rule.owner or cat.owner_spec
        for command in plan_path(
            path, rule, owner, config,
            is_dir=is_dir, acl_enabled=acl_enabled,
            principals_available=principals_available,
        ):
            runner.run(command)

    # Directory tree (mkdir -p is idempotent, so an existing category dir is fine).
    apply_rule(config.root_dir / req.category, "category_dir", is_dir=True)
    apply_rule(svc_path, "service_dir", is_dir=True)
    apply_rule(svc_path / "config", "config_dir", is_dir=True)
    apply_rule(svc_path / "data", "data_dir", is_dir=True)

    # Empty compose.yaml and .env — left for the operator to fill in.
    compose_file = svc_path / "compose.yaml"
    runner.write_file(compose_file, "")
    apply_rule(compose_file, "compose_file", is_dir=False)

    env_file = svc_path / ".env"
    runner.write_file(env_file, "")
    apply_rule(env_file, "env_file", is_dir=False)

    # service.yaml — dashboard descriptor (template, public: false by default).
    service_file = svc_path / SERVICE_FILENAME
    runner.write_file(service_file, scaffold_template(req.category, req.service))
    apply_rule(service_file, "service_file", is_dir=False)

    return runner.executed
