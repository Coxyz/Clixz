"""Update the two editable files of an existing service.

Only ``compose.yaml`` and ``service.yaml`` can be rewritten. Everything else in
a service tree is off limits by design:

- ``.env`` holds secrets (600 root:root) and must never be reachable through an
  automated path;
- ``config/`` and ``data/`` hold live application state, whose corruption is not
  recoverable from this tool.

The guard is positive, not a blacklist: the target must be one of the two names
in :data:`UPDATABLE`, resolved from a fixed table rather than from caller input.

Every write is validated (the content must parse, and a descriptor must satisfy
the same rules as ``meta validate``), snapshotted into the archive tree, then
written atomically and brought back to its configured owner/mode/ACL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .archive import snapshot_file
from .config import Config
from .meta import SERVICE_FILENAME, parse_meta
from .policy import plan_path
from .system import CommandRunner

COMPOSE_FILENAME = "compose.yaml"

# target keyword → (file name, rule name in the config)
UPDATABLE: dict[str, tuple[str, str]] = {
    "compose": (COMPOSE_FILENAME, "compose_file"),
    "service": (SERVICE_FILENAME, "service_file"),
}

# Never writable through this command. Kept for the error message: the guard
# itself is the UPDATABLE lookup, not this set.
PROTECTED = (".env", "config/", "data/")

MAX_BYTES = 512 * 1024


@dataclass(frozen=True)
class UpdateRequest:
    category: str
    service: str
    target: str
    content: str


@dataclass
class UpdateResult:
    path: Path
    previous: str
    content: str
    snapshot: Path | None = None
    commands: list[list[str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def unchanged(self) -> bool:
        return self.previous == self.content


def validate_target(target: str) -> tuple[str, str]:
    """Resolve a target keyword to (file name, rule name), or raise."""
    try:
        return UPDATABLE[target]
    except KeyError:
        raise ValueError(
            f"Invalid target '{target}'. Updatable: {', '.join(sorted(UPDATABLE))}. "
            f"Never updatable: {', '.join(PROTECTED)}."
        ) from None


def _normalise(content: str) -> str:
    if len(content.encode("utf-8")) > MAX_BYTES:
        raise ValueError(f"Content too large (max {MAX_BYTES} bytes).")
    if not content.strip():
        raise ValueError("Refusing to write empty content.")
    return content if content.endswith("\n") else content + "\n"


def _parse_yaml(content: str, what: str) -> object:
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"{what} is not valid YAML: {exc}") from None


def validate_content(category: str, service: str, target: str, content: str) -> list[str]:
    """Validate content for the given target. Returns warnings; raises on error."""
    data = _parse_yaml(content, target)
    if not isinstance(data, dict):
        raise ValueError(f"{target} must be a YAML mapping at the top level.")

    if target == "compose":
        services = data.get("services")
        if not isinstance(services, dict) or not services:
            raise ValueError("compose.yaml must define a non-empty 'services' mapping.")
        return []

    # target == "service": reuse the descriptor rules so `update` can never
    # write something `check` would then flag as an error. A ``None`` meta means
    # a hard error; issues alongside a parsed meta are soft warnings.
    meta, issues = parse_meta(data, category, service)
    if meta is None:
        raise ValueError("Invalid descriptor: " + "; ".join(issues))
    return issues


def update_from_patch(
    config: Config,
    category: str,
    service: str,
    patch: object,
    *,
    dry_run: bool,
    acl_enabled: bool,
    principals_available: dict[str, bool],
) -> tuple[UpdateResult, UpdateResult]:
    """Patch a service's stored spec, then regenerate its compose.yaml.

    The caller sends only the fields it wants to change; the merged spec is
    re-validated in full, so a patch can never leave the service in a state the
    spec module would have refused to create. Returns ``(compose, spec)``
    results — the compose is written first, because a spec.json that no longer
    matches the deployed compose is the more confusing failure.
    """
    from .spec import (  # local import: spec imports scaffold, which imports policy
        SPEC_FILENAME,
        apply_patch,
        load_spec,
        render_compose,
        spec_json,
        spec_path,
        validate,
    )

    current = load_spec(config, category, service)
    merged = validate(apply_patch(current, patch), config)

    compose_result = update_service(
        config,
        UpdateRequest(category, service, "compose", render_compose(merged, config)),
        dry_run=dry_run, acl_enabled=acl_enabled,
        principals_available=principals_available,
    )

    path = spec_path(config, category, service)
    previous = path.read_text(encoding="utf-8") if path.is_file() else ""
    content = spec_json(merged)
    spec_result = UpdateResult(path=path, previous=previous, content=content)
    if not spec_result.unchanged:
        runner = CommandRunner(dry_run=dry_run)
        runner.write_file(path, content)
        rule = config.rule_or_default("spec_file")
        owner = rule.owner or config.category(category).owner_spec
        for command in plan_path(
            path, rule, owner, config, is_dir=False,
            acl_enabled=acl_enabled, principals_available=principals_available,
        ):
            runner.run(command)
        spec_result.commands = runner.executed
    return compose_result, spec_result


def update_service(
    config: Config,
    req: UpdateRequest,
    *,
    dry_run: bool,
    acl_enabled: bool,
    principals_available: dict[str, bool],
) -> UpdateResult:
    """Rewrite one editable file of a service, then restore its owner/mode/ACL."""
    filename, rule_name = validate_target(req.target)
    content = _normalise(req.content)
    warnings = validate_content(req.category, req.service, req.target, content)

    svc_path = config.root_dir / req.category / req.service
    if not svc_path.is_dir():
        raise RuntimeError(f"No such service: {req.category}/{req.service}")

    path = svc_path / filename
    # Defence in depth: the target came from a fixed table, but a symlinked
    # service.yaml would still escape the tree without this check.
    resolved = path.resolve()
    if resolved.parent != svc_path.resolve():
        raise RuntimeError(f"{filename} resolves outside {svc_path} — refusing to write.")

    previous = path.read_text(encoding="utf-8") if path.is_file() else ""
    result = UpdateResult(path=path, previous=previous, content=content, warnings=warnings)
    if result.unchanged:
        return result

    if previous:
        result.snapshot = snapshot_file(config, req.category, req.service, path, dry_run=dry_run)

    runner = CommandRunner(dry_run=dry_run)
    runner.write_file(path, content)
    rule = config.rule_or_default(rule_name)
    owner = rule.owner or config.category(req.category).owner_spec
    for command in plan_path(
        path, rule, owner, config, is_dir=False,
        acl_enabled=acl_enabled, principals_available=principals_available,
    ):
        runner.run(command)
    result.commands = runner.executed
    return result
