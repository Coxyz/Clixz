"""Plans: what a change would do, stored by root, checked again before it runs.

Until 2.3 the MCP server could only *show* a plan and hand the operator a
command to type. Now a plan prepared through the MCP can be applied there too,
once the operator approves the ``plan_apply`` call in the Claude client. What
keeps that safe is in this module:

- a plan is **computed** without writing anything, and **blocked** — never
  stored — when the result would carry an error-level lint finding that
  ``ignore.yaml`` does not accept (privileged, the Docker socket, ``/``…), or
  an invalid ``service.yaml``. Neither file is writable by the AI, so a compose
  cannot be used to hand it root;
- a plan is **stored** by root alone (``plans/`` is 0700), under a random id.
  Nothing outside root can write a plan, so an id is proof that clixz computed
  it — no signature needed;
- at apply time the plan is **recomputed** from its request against the disk
  as it is now. A plan whose service changed in between (a compose edited by
  hand or in Komodo) is refused rather than applied over the change;
- a plan is **used once** and **expires** after an hour.

``.env`` is never written by a plan: ``new`` creates it empty, Komodo fills it.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import compose as compose_mod
from . import komodo as komodo_mod
from .archive import archive_service
from .config import Config
from .meta import SERVICE_FILENAME, parse_meta, scaffold_template, write_manifest
from .policy import COMPOSE, apply_fixes, audit_all, audit_service, order_fixes, resolve_service
from .scaffold import CreateRequest, create_service, edit_service, plan_create, validate_service_name
from .system import CommandExecutionError

ACTIONS = ("new", "edit", "fix", "rm")
PLAN_TTL = timedelta(hours=1)
KEEP_EXPIRED = timedelta(hours=24)
MAX_COMPOSE = 128 * 1024
MAX_SERVICE_YAML = 32 * 1024
PLAN_ID_RE = re.compile(r"^[0-9a-f]{8}$")
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$")
STACK_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_TIME = "%Y-%m-%dT%H:%M:%SZ"


class PlanError(ValueError):
    """A plan request or a plan id that cannot be honoured. Caller-facing."""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, _TIME).replace(tzinfo=timezone.utc)


# ─── request ─────────────────────────────────────────────────────────────────

def _optional_text(raw: dict, key: str, limit: int) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise PlanError(f"'{key}' must be a string")
    if len(value.encode("utf-8")) > limit:
        raise PlanError(f"'{key}' is larger than {limit // 1024} KiB")
    return value


@dataclass
class Request:
    """What was asked for. Validated here, whoever sent it."""

    action: str
    service: str | None = None
    compose: str | None = None
    service_yaml: str | None = None
    stack: str | None = None

    @classmethod
    def from_dict(cls, raw: object) -> "Request":
        if not isinstance(raw, dict):
            raise PlanError("a plan request must be an object")
        action = raw.get("action")
        if action not in ACTIONS:
            raise PlanError(f"unknown action {action!r} (known: {', '.join(ACTIONS)})")
        service = raw.get("service")
        if service is not None and (not isinstance(service, str) or not SERVICE_RE.match(service)):
            raise PlanError(f"invalid service name: {service!r}")
        if service is None and action != "fix":
            raise PlanError(f"'{action}' needs a service")
        compose = _optional_text(raw, "compose", MAX_COMPOSE)
        service_yaml = _optional_text(raw, "service_yaml", MAX_SERVICE_YAML)
        if action not in ("new", "edit") and (compose is not None or service_yaml is not None):
            raise PlanError("compose and service_yaml only go with 'new' and 'edit'")
        stack = raw.get("stack")
        if stack is not None:
            if action != "new":
                raise PlanError("'stack' only goes with 'new'")
            if not isinstance(stack, str) or not STACK_RE.match(stack):
                raise PlanError(f"invalid stack name: {stack!r}")
        return cls(action=str(action), service=service, compose=compose,
                   service_yaml=service_yaml, stack=stack)

    def to_dict(self) -> dict:
        return {"action": self.action, "service": self.service, "compose": self.compose,
                "service_yaml": self.service_yaml, "stack": self.stack}


# ─── plan ────────────────────────────────────────────────────────────────────

@dataclass
class Plan:
    action: str
    target: str
    request: Request
    commands: list[list[str]] = field(default_factory=list)
    diff: str = ""
    lint: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    fingerprint: str = ""
    id: str | None = None
    created_at: str | None = None
    expires_at: str | None = None
    origin: str = "cli"

    def status(self, now: datetime | None = None) -> str:
        if self.blocked:
            return "blocked"
        if self.expires_at and (now or _now()) > _parse_time(self.expires_at):
            return "expired"
        return "pending"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "action": self.action, "target": self.target,
            "status": self.status(), "origin": self.origin,
            "created_at": self.created_at, "expires_at": self.expires_at,
            "commands": self.commands, "diff": self.diff, "lint": self.lint,
            "warnings": self.warnings, "blocked": self.blocked,
            "fingerprint": self.fingerprint, "request": self.request.to_dict(),
        }

    def summary(self) -> dict:
        """What a listing shows: no file contents, no diff."""
        return {"id": self.id, "action": self.action, "target": self.target,
                "status": self.status(), "origin": self.origin,
                "created_at": self.created_at, "expires_at": self.expires_at,
                "commands": len(self.commands), "warnings": len(self.warnings)}

    @classmethod
    def from_dict(cls, raw: dict) -> "Plan":
        try:
            return cls(
                action=str(raw["action"]), target=str(raw["target"]),
                request=Request.from_dict(raw["request"]),
                commands=[list(map(str, c)) for c in raw.get("commands") or []],
                diff=str(raw.get("diff") or ""), lint=list(raw.get("lint") or []),
                warnings=list(raw.get("warnings") or []),
                blocked=list(raw.get("blocked") or []),
                fingerprint=str(raw.get("fingerprint") or ""),
                id=raw.get("id"), created_at=raw.get("created_at"),
                expires_at=raw.get("expires_at"), origin=str(raw.get("origin") or "cli"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"unreadable plan: {exc}") from exc


def _digest(*parts: object) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode("utf-8")).hexdigest()


def _sha(text: str | None) -> str | None:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None


def _diff(old: str | None, new: str, name: str) -> str:
    lines = difflib.unified_diff(
        (old or "").splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"a/{name}" if old is not None else "/dev/null", tofile=f"b/{name}",
    )
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _check_compose(config: Config, service_key: str, text: str, svc_dir: Path,
                   blocked: list[str]) -> list[dict]:
    """Lint ``text`` as this service's compose; block on unaccepted errors.

    Structure is checked apart from the lint: a plan never writes something
    that is not a compose file, whatever level ``lint.yaml`` gives to
    ``compose-empty`` or ``compose-invalid``.
    """
    try:
        doc = yaml.safe_load(text) if text.strip() else None
    except yaml.YAMLError:
        doc = None
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict) or not services:
        blocked.append("compose: not a compose file — a YAML mapping with a non-empty "
                       "'services' mapping is expected")
    rows = []
    for finding in compose_mod.lint_text(text, svc_dir, config.policy.lint):
        accepted = config.policy.ignored(service_key, finding.rule)
        rows.append({"service": finding.service, "level": finding.level, "rule": finding.rule,
                     "message": finding.message,
                     "ignored": accepted.reason if accepted else None})
        if finding.level == "error" and accepted is None:
            where = f"{finding.service}: " if finding.service else ""
            blocked.append(f"compose: {where}{finding.message} ({finding.rule}) — an error in "
                           "lint.yaml, not accepted in ignore.yaml")
    return rows


def _check_service_yaml(category: str, name: str, text: str, blocked: list[str],
                        warnings: list[str]) -> None:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        blocked.append(f"service.yaml: not valid YAML: {exc}")
        return
    meta, issues = parse_meta(raw, category, name)
    (blocked if meta is None else warnings).extend(f"service.yaml: {i}" for i in issues)


def _resolve(config: Config, service: str, blocked: list[str]) -> tuple[str, str, Path] | None:
    try:
        return resolve_service(config, service)
    except KeyError as exc:
        blocked.append(str(exc).strip("'\""))
        return None


def _plan_new(config: Config, request: Request) -> Plan:
    assert request.service is not None
    blocked: list[str] = []
    warnings: list[str] = []
    category, _, name = request.service.partition("/")
    plan = Plan(action="new", target=request.service, request=request)
    if not name:
        blocked.append("give the service as category/service, e.g. apps/myapp")
    else:
        try:
            validate_service_name(name)
        except ValueError as exc:
            blocked.append(str(exc))
    if category not in config.categories:
        blocked.append(f"Unknown category '{category}'. "
                       f"Authorized: {', '.join(sorted(config.categories))}")
    if blocked:
        plan.blocked = blocked
        return plan

    svc_dir = config.root_dir / category / name
    compose = (request.compose if request.compose is not None
               else compose_mod.template(config, category, name))
    service_yaml = (request.service_yaml if request.service_yaml is not None
                    else scaffold_template(category, name))
    try:
        plan.commands = plan_create(config, CreateRequest(category, name, compose, service_yaml))
    except (KeyError, ValueError, RuntimeError) as exc:
        blocked.append(str(exc))
    plan.lint = _check_compose(config, request.service, compose, svc_dir, blocked)
    _check_service_yaml(category, name, service_yaml, blocked, warnings)
    if config.komodo.enabled:
        plan.commands.append(["komodo", "CreateStack", request.stack or name,
                              f"{config.komodo.run_root}/{category}/{name}"])
    plan.diff = _diff(None, compose, COMPOSE) + _diff(None, service_yaml, SERVICE_FILENAME)
    plan.blocked, plan.warnings = blocked, warnings
    plan.fingerprint = _digest(request.to_dict(), "absent")
    return plan


def _plan_edit(config: Config, request: Request) -> Plan:
    assert request.service is not None
    blocked: list[str] = []
    warnings: list[str] = []
    plan = Plan(action="edit", target=request.service, request=request)
    resolved = _resolve(config, request.service, blocked)
    if resolved is None:
        plan.blocked = blocked
        return plan
    category, name, path = resolved
    target = f"{category}/{name}"
    request = replace(request, service=target)
    plan.target, plan.request = target, request

    # Before reading anything: the diff would show a link's target — maybe a
    # .env — to whoever asked for the plan.
    linked = [p for p in (path, path / COMPOSE, path / SERVICE_FILENAME) if p.is_symlink()]
    if linked:
        plan.blocked = [f"{p} is a symlink — refusing to read or write through it" for p in linked]
        return plan

    current_compose, current_service = _read(path / COMPOSE), _read(path / SERVICE_FILENAME)
    compose = request.compose if request.compose != current_compose else None
    service_yaml = request.service_yaml if request.service_yaml != current_service else None
    if request.compose is None and request.service_yaml is None:
        blocked.append("nothing to change: give compose and/or service_yaml")
    elif compose is None and service_yaml is None:
        blocked.append("identical to the current files: nothing to change")
    if blocked:
        plan.blocked = blocked
        return plan

    if compose is not None:
        plan.lint = _check_compose(config, target, compose, path, blocked)
        plan.diff += _diff(current_compose, compose, COMPOSE)
    if service_yaml is not None:
        _check_service_yaml(category, name, service_yaml, blocked, warnings)
        plan.diff += _diff(current_service, service_yaml, SERVICE_FILENAME)
    try:
        plan.commands = edit_service(config, category, name, compose=compose,
                                     service_yaml=service_yaml, dry_run=True)
    except (KeyError, RuntimeError) as exc:
        blocked.append(str(exc))
    plan.blocked, plan.warnings = blocked, warnings
    plan.fingerprint = _digest(request.to_dict(), _sha(current_compose), _sha(current_service))
    return plan


def _plan_fix(config: Config, request: Request) -> Plan:
    blocked: list[str] = []
    plan = Plan(action="fix", target="all services", request=request)
    if request.service:
        resolved = _resolve(config, request.service, blocked)
        if resolved is None:
            plan.blocked = blocked
            return plan
        category, name, _ = resolved
        plan.target = f"{category}/{name}"
        plan.request = replace(request, service=plan.target)
        reports = [audit_service(config, category, name)]
    else:
        reports = audit_all(config)
    plan.commands = order_fixes([fix for r in reports for fix in r.fixes])
    if not plan.commands:
        blocked.append("nothing to fix")
    plan.blocked = blocked
    plan.fingerprint = _digest(plan.request.to_dict(), plan.commands)
    return plan


def _plan_rm(config: Config, request: Request) -> Plan:
    assert request.service is not None
    blocked: list[str] = []
    plan = Plan(action="rm", target=request.service, request=request)
    resolved = _resolve(config, request.service, blocked)
    if resolved is None:
        plan.blocked = blocked
        return plan
    category, name, path = resolved
    plan.target = f"{category}/{name}"
    plan.request = replace(request, service=plan.target)
    archive = config.root_dir / ".archive" / category / name / "<timestamp>"
    plan.commands = [["mv", str(path), str(archive)]]
    plan.warnings = ["the service is archived, not deleted; its Komodo stack, if any, stays — "
                     "stop and delete it in Komodo"]
    plan.fingerprint = _digest(plan.request.to_dict(), "present")
    return plan


def compute(config: Config, request: Request) -> Plan:
    """The plan for ``request`` against the disk as it is. Writes nothing."""
    return {"new": _plan_new, "edit": _plan_edit, "fix": _plan_fix,
            "rm": _plan_rm}[request.action](config, request)


# ─── store ───────────────────────────────────────────────────────────────────

def _check_id(plan_id: object) -> str:
    if not isinstance(plan_id, str) or not PLAN_ID_RE.match(plan_id):
        raise PlanError(f"invalid plan id: {plan_id!r} (8 hexadecimal characters)")
    return plan_id


def _plans_dir(config: Config) -> Path:
    return config.state.plans_dir


def _load_path(path: Path) -> Plan:
    try:
        return Plan.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except ValueError as exc:
        raise PlanError(f"unreadable plan {path.name}: {exc}") from exc


def _purge(directory: Path, now: datetime) -> None:
    """Forget plans expired for more than a day, and claims left by a crash."""
    for path in directory.glob("*.json"):
        try:
            plan = _load_path(path)
            if plan.expires_at and now - _parse_time(plan.expires_at) > KEEP_EXPIRED:
                path.unlink(missing_ok=True)
        except (PlanError, OSError, ValueError):
            continue
    for path in directory.glob("*.applying"):
        try:
            if now.timestamp() - path.stat().st_mtime > PLAN_TTL.total_seconds():
                path.unlink(missing_ok=True)
        except OSError:
            continue


def save(config: Config, plan: Plan, origin: str) -> Plan:
    """Store a computed plan under a fresh id. Root's directory, 0600 files."""
    if plan.blocked:
        raise PlanError("a blocked plan cannot be saved: " + "; ".join(plan.blocked))
    directory = _plans_dir(config)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    now = _now()
    _purge(directory, now)
    while True:
        plan_id = secrets.token_hex(4)
        path = directory / f"{plan_id}.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:  # pragma: no cover - 1 in 4 billion
            continue
    stored = replace(plan, id=plan_id, created_at=now.strftime(_TIME),
                     expires_at=(now + PLAN_TTL).strftime(_TIME), origin=origin)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(stored.to_dict(), f, ensure_ascii=False, indent=2)
    return stored


def load(config: Config, plan_id: str) -> Plan:
    path = _plans_dir(config) / f"{_check_id(plan_id)}.json"
    if not path.is_file():
        raise PlanError(f"no pending plan {plan_id} — applied, deleted, or never made")
    return _load_path(path)


def list_plans(config: Config) -> list[Plan]:
    directory = _plans_dir(config)
    if not directory.is_dir():
        return []
    _purge(directory, _now())
    found = []
    for path in directory.glob("*.json"):
        try:
            found.append(_load_path(path))
        except PlanError:
            continue
    return sorted(found, key=lambda p: p.created_at or "")


def drop(config: Config, plan_id: str) -> Plan:
    plan = load(config, plan_id)
    (_plans_dir(config) / f"{plan_id}.json").unlink(missing_ok=True)
    return plan


# ─── execution ───────────────────────────────────────────────────────────────

@dataclass
class Outcome:
    plan: Plan
    ok: bool
    executed: list[list[str]] = field(default_factory=list)
    failed: list[tuple[list[str], str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "plan_id": self.plan.id, "action": self.plan.action,
                "target": self.plan.target, "executed": self.executed,
                "failed": [{"command": c, "error": e} for c, e in self.failed],
                "warnings": self.warnings, "notes": self.notes}


def _refresh_manifest(config: Config, outcome: Outcome) -> None:
    try:
        result = write_manifest(config)
    except OSError as exc:
        outcome.warnings.append(f"manifest.json not refreshed: {exc}")
        return
    if result.errors:
        outcome.warnings.append(f"manifest.json not refreshed: {len(result.errors)} invalid "
                                "service.yaml — see `clixz meta`")


def execute(config: Config, plan: Plan, *, komodo_client: object = None) -> Outcome:
    """Carry out a computed, unblocked plan. The CLI verbs and ``apply`` share it."""
    if plan.blocked:
        raise PlanError("a blocked plan cannot run: " + "; ".join(plan.blocked))
    request = plan.request
    outcome = Outcome(plan=plan, ok=True, warnings=list(plan.warnings))
    category, _, name = plan.target.partition("/")
    try:
        if plan.action == "new":
            outcome.executed = create_service(config, CreateRequest(
                category, name, request.compose, request.service_yaml))
        elif plan.action == "edit":
            outcome.executed = edit_service(config, category, name, compose=request.compose,
                                            service_yaml=request.service_yaml)
        elif plan.action == "fix":
            result = apply_fixes(plan.commands)
            outcome.executed, outcome.failed = result.executed, result.failed
            outcome.ok = not result.failed
        elif plan.action == "rm":
            outcome.executed = archive_service(config, category, name, dry_run=False).commands
    except (CommandExecutionError, RuntimeError, OSError, KeyError, ValueError) as exc:
        outcome.ok = False
        outcome.failed.append(([plan.action, plan.target], str(exc)))
        return outcome

    if plan.action in ("new", "rm") or (plan.action == "edit" and request.service_yaml):
        _refresh_manifest(config, outcome)
    if plan.action == "new" and config.komodo.enabled:
        try:
            outcome.notes.append(komodo_mod.create_stack(
                config, name=request.stack or name,
                run_directory=f"{config.komodo.run_root}/{category}/{name}",
                client=komodo_client))
        except komodo_mod.KomodoError as exc:
            outcome.warnings.append(f"the service is created but its Komodo stack is not: {exc}. "
                                    "Create it in Komodo (files on host, run directory "
                                    f"{config.komodo.run_root}/{category}/{name}).")
    return outcome


def apply(config: Config, plan_id: str, *, komodo_client: object = None) -> Outcome:
    """Apply a stored plan once, if it still describes the disk."""
    directory = _plans_dir(config)
    source = directory / f"{_check_id(plan_id)}.json"
    claimed = directory / f"{plan_id}.applying"
    try:
        # The rename is the claim: of two simultaneous applies, one gets it.
        os.rename(source, claimed)
    except FileNotFoundError as exc:
        raise PlanError(f"no pending plan {plan_id} — applied, deleted, or never made") from exc
    try:
        stored = _load_path(claimed)
        if stored.status() == "expired":
            raise PlanError(f"plan {plan_id} expired at {stored.expires_at} — make a new one")
        fresh = compute(config, stored.request)
        if fresh.blocked:
            raise PlanError(f"plan {plan_id} no longer applies: " + "; ".join(fresh.blocked))
        if fresh.fingerprint != stored.fingerprint:
            raise PlanError(f"{stored.target} changed since plan {plan_id} was made — "
                            "nothing was written; make a new plan")
        fresh = replace(fresh, id=stored.id, created_at=stored.created_at,
                        expires_at=stored.expires_at, origin=stored.origin)
        return execute(config, fresh, komodo_client=komodo_client)
    finally:
        claimed.unlink(missing_ok=True)
