"""Plans: what a change would do, stored by root, checked again before it runs.

Until 2.3 the MCP server could only *show* a plan and hand the operator a
command to type. Now a plan prepared through the MCP can be applied there too,
once the operator approves the ``plan_apply`` call in the Claude client. What
keeps that safe is in this module:

- a plan is **computed** without writing anything, and **blocked** — never
  stored — when the result would carry an error-level lint finding that
  ``ignore.yaml`` does not accept (privileged, the Docker socket, ``/``…), or
  an invalid ``service.yaml``. ``lint.yaml`` is not writable by the AI, and
  ``ignore.yaml`` only through an ``ignore`` plan that cannot accept an
  error-level rule (see :func:`_plan_ignore`), so a compose cannot be used to
  hand it root;
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
import fnmatch
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
from .archive import archive_service, snapshot_file
from .config import Config
from .meta import SERVICE_FILENAME, parse_meta, scaffold_template, write_manifest
from .policy import (
    COMPOSE,
    apply_fixes,
    audit_all,
    audit_service,
    list_services,
    order_fixes,
    resolve_service,
)
from .rules import IGNORE_FILE, Ignore, parse_ignores
from .scaffold import CreateRequest, create_service, edit_service, plan_create, validate_service_name
from .system import CommandExecutionError, CommandRunner

ACTIONS = ("new", "edit", "fix", "rm", "ignore")
# Actions that act on no service: fix (all of them, when none is given) and
# ignore (the host's ignore.yaml).
_SERVICELESS = ("fix", "ignore")
PLAN_TTL = timedelta(hours=1)
KEEP_EXPIRED = timedelta(hours=24)
MAX_COMPOSE = 128 * 1024
MAX_SERVICE_YAML = 32 * 1024
MAX_IGNORE = 64 * 1024
# Where the previous ignore.yaml is kept: .archive/clixz/config/updates/.
IGNORE_ARCHIVE = ("clixz", "config")
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
    ignore: str | None = None   # the whole new ignore.yaml, for 'ignore'

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
        if service is None and action not in _SERVICELESS:
            raise PlanError(f"'{action}' needs a service")
        if service is not None and action == "ignore":
            raise PlanError("'ignore' replaces the host's ignore.yaml: it takes no service")
        compose = _optional_text(raw, "compose", MAX_COMPOSE)
        service_yaml = _optional_text(raw, "service_yaml", MAX_SERVICE_YAML)
        if action not in ("new", "edit") and (compose is not None or service_yaml is not None):
            raise PlanError("compose and service_yaml only go with 'new' and 'edit'")
        ignore = _optional_text(raw, "ignore", MAX_IGNORE)
        if action == "ignore" and ignore is None:
            raise PlanError("'ignore' needs the whole new ignore.yaml in 'ignore'")
        if action != "ignore" and ignore is not None:
            raise PlanError("'ignore' (the file) only goes with the 'ignore' action")
        stack = raw.get("stack")
        if stack is not None:
            if action != "new":
                raise PlanError("'stack' only goes with 'new'")
            if not isinstance(stack, str) or not STACK_RE.match(stack):
                raise PlanError(f"invalid stack name: {stack!r}")
        return cls(action=str(action), service=service, compose=compose,
                   service_yaml=service_yaml, stack=stack, ignore=ignore)

    def to_dict(self) -> dict:
        out = {"action": self.action, "service": self.service, "compose": self.compose,
               "service_yaml": self.service_yaml, "stack": self.stack}
        # Only when set: the other actions keep the request — and so the
        # fingerprint — they had before 'ignore' existed.
        if self.ignore is not None:
            out["ignore"] = self.ignore
        return out


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


def _error_acceptances(config: Config, entries: tuple[Ignore, ...]) -> set[tuple[str, str]]:
    """The (service pattern, rule) pairs that accept a rule ``lint.yaml`` makes an error."""
    levels = config.policy.lint.levels
    return {(entry.service, rule) for entry in entries for rule in entry.rules
            if levels.get(rule) == "error"}


def _parse_ignore_text(text: str, issues: list[str]) -> tuple[Ignore, ...] | None:
    """The entries of an ignore.yaml text; None when it is not one at all."""
    try:
        raw = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError as exc:
        issues.append(f"{IGNORE_FILE}: not valid YAML: {exc}")
        return None
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        issues.append(f"{IGNORE_FILE}: top-level YAML must be a mapping")
        return None
    return parse_ignores(raw, issues)


def write_ignore(config: Config, text: str, *, dry_run: bool = False) -> list[list[str]]:
    """Replace the host's ignore.yaml with ``text``; return the commands.

    The previous file is copied under ``.archive/clixz/config/updates/`` first.
    The new content is written in place, so the file keeps its owner and mode;
    a file that did not exist yet is made 0644, like `clixz rules --edit-ignore`.
    """
    if config.config_dir is None:
        raise RuntimeError("no config file in use — ignore.yaml lives next to it")
    path = config.config_dir / IGNORE_FILE
    # Written as root: through a link, the write would land on its target.
    if path.is_symlink():
        raise RuntimeError(f"{path} is a symlink — refusing to write through it")
    runner = CommandRunner(dry_run=dry_run)
    commands: list[list[str]] = []
    existed = path.exists()
    if existed:
        snapshot = snapshot_file(config, *IGNORE_ARCHIVE, path, dry_run=dry_run)
        commands += [["mkdir", "-p", str(snapshot.parent)],
                     ["cp", "-p", str(path), str(snapshot)]]
    runner.write_file(path, text)
    if not existed:
        runner.run(["chmod", "644", str(path)])
    return commands + runner.executed


def _plan_ignore(config: Config, request: Request) -> Plan:
    """Replace ignore.yaml — never to accept an error-level rule.

    Accepting a ``warn`` or ``info`` finding changes what `clixz check` shows
    and nothing else: such findings never block a plan. Accepting an
    ``error`` one would unblock plans — a privileged compose, the Docker
    socket — so the pairs (service, rule) at error level in ``lint.yaml`` must
    all be in the current file already. The AI can keep them, reword their
    reason or remove them; adding one stays the operator's decision, by hand.
    """
    assert request.ignore is not None
    blocked: list[str] = []
    warnings: list[str] = []
    plan = Plan(action="ignore", target=IGNORE_FILE, request=request)
    if config.config_dir is None:
        plan.blocked = ["no config file in use — ignore.yaml lives next to it"]
        return plan
    path = config.config_dir / IGNORE_FILE
    plan.target = str(path)
    if path.is_symlink():
        plan.blocked = [f"{path} is a symlink — refusing to read or write through it"]
        return plan

    current = _read(path)
    if request.ignore == current:
        plan.blocked = ["identical to the current ignore.yaml: nothing to change"]
        return plan

    entries = _parse_ignore_text(request.ignore, blocked)
    if entries is not None:
        # A problem parse_ignores reports (no reason, unknown rule, unknown key)
        # would be silently dropped when the file is read: a plan never writes
        # one.
        current_entries = (_parse_ignore_text(current, []) or ()) if current else ()
        added = _error_acceptances(config, entries) - _error_acceptances(config, current_entries)
        for service, rule in sorted(added):
            blocked.append(
                f"{IGNORE_FILE}: accepting '{rule}' for {service} — an error in lint.yaml — "
                "is the operator's decision, not a plan's: `sudo clixz rules --edit-ignore`")
        known = [f"{c}/{s}" for c, s, _ in list_services(config)]
        for entry in entries:
            if not any(fnmatch.fnmatchcase(svc, entry.service) for svc in known):
                warnings.append(f"{IGNORE_FILE}: '{entry.service}' matches no service "
                                "(a typo, or a service since removed?)")
    if blocked:
        plan.blocked = blocked
        return plan

    plan.diff = _diff(current, request.ignore, IGNORE_FILE)
    try:
        plan.commands = write_ignore(config, request.ignore, dry_run=True)
    except RuntimeError as exc:
        blocked.append(str(exc))
    plan.blocked, plan.warnings = blocked, warnings
    plan.fingerprint = _digest(request.to_dict(), _sha(current))
    return plan


def compute(config: Config, request: Request) -> Plan:
    """The plan for ``request`` against the disk as it is. Writes nothing."""
    return {"new": _plan_new, "edit": _plan_edit, "fix": _plan_fix,
            "rm": _plan_rm, "ignore": _plan_ignore}[request.action](config, request)


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
        elif plan.action == "ignore":
            assert request.ignore is not None
            outcome.executed = write_ignore(config, request.ignore)
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
