"""The compose rules and the accepted exceptions, as two files the operator owns.

Until 2.2 the lint levels were constants in ``compose.py``: changing "an image
on ``:latest`` is a warning" into an error meant editing the package. They are
now data, read from two files that sit next to ``config.yaml``:

``lint.yaml``
    The level of each rule (``error``, ``warn``, ``info``, ``off``) and the host
    paths a container must not mount. This is policy: what the house considers
    a problem.

``ignore.yaml``
    Findings that were looked at and accepted, per service, each with its
    reason. This is not policy, it is the list of decisions taken against it —
    which is why it lives in its own file: it changes for different reasons, and
    a reviewer wants to read it on its own.

Both are optional. Without them clixz behaves exactly as 2.1 did.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

import yaml

LINT_FILE = "lint.yaml"
IGNORE_FILE = "ignore.yaml"

LEVELS = ("error", "warn", "info", "off")


@dataclass(frozen=True)
class RuleSpec:
    id: str
    level: str      # the built-in default
    summary: str


# Every compose rule, with its default level. The ids are the public interface:
# they are what lint.yaml and ignore.yaml refer to, so renaming one is a
# breaking change.
LINT_RULES: tuple[RuleSpec, ...] = (
    RuleSpec("privileged", "error", "privileged: true"),
    RuleSpec("network-host", "error", "network_mode: host"),
    RuleSpec("pid-host", "error", "pid: host"),
    RuleSpec("mount-critical", "error", "mounts a path listed in mounts.critical"),
    RuleSpec("mount-root", "error", "mounts /"),
    RuleSpec("mount-config-rw", "error",
             "mounts a path listed in mounts.critical_if_writable, read-write"),
    RuleSpec("mount-config-ro", "info",
             "mounts a path listed in mounts.critical_if_writable, read-only"),
    RuleSpec("mount-host", "warn", "mounts a host path outside the service directory"),
    RuleSpec("no-image", "error", "neither image nor build"),
    RuleSpec("image-untagged", "warn", "image without a tag"),
    RuleSpec("image-latest", "warn", "image pinned to :latest"),
    RuleSpec("port-all-interfaces", "warn", "port published on every interface"),
    RuleSpec("no-cap-drop", "warn", "no cap_drop: [ALL]"),
    RuleSpec("no-new-privileges", "warn", "no security_opt: [no-new-privileges:true]"),
    RuleSpec("no-restart", "warn", "no restart policy"),
    RuleSpec("no-log-rotation", "warn", "no logging max-size"),
    RuleSpec("no-user", "info", "no user:"),
    RuleSpec("no-healthcheck", "info", "no healthcheck"),
    RuleSpec("extra-privileges", "info", "cap_add, devices or sysctls in use"),
    RuleSpec("compose-empty", "warn", "compose.yaml is empty"),
    RuleSpec("compose-invalid", "error",
             "compose.yaml is unreadable, declares no services, or a service is not a mapping"),
)

# Permission findings. Their severity is not configurable — a wrong owner is
# drift from a rule in config.yaml, not advice — but they can be ignored.
AUDIT_RULES: tuple[RuleSpec, ...] = (
    RuleSpec("missing-dir", "error", "a directory of the skeleton is missing"),
    RuleSpec("missing-file", "warn", "compose.yaml, service.yaml or .env is missing"),
    RuleSpec("owner", "error", "owner differs from the rule"),
    RuleSpec("mode", "error", "mode differs from the rule"),
    RuleSpec("acl", "warn", "POSIX ACL entries left by v1"),
)

LINT_IDS = tuple(r.id for r in LINT_RULES)
IGNORABLE_IDS = LINT_IDS + tuple(r.id for r in AUDIT_RULES)

# Host paths that hand over the machine however they are mounted. Read-only
# changes nothing here: :ro on a socket still lets you talk to the daemon, and
# read access to /etc/shadow or /root/.ssh is the whole prize.
DEFAULT_CRITICAL = (
    "/var/run/docker.sock", "/run/docker.sock", "/var/lib/docker",
    "/etc/shadow", "/root", "/boot",
)

# Paths that hand over the machine only when writable. Read-only, they are
# ordinary configuration a container may legitimately need — the MCP container
# reads /etc/clixz/config.yaml to answer questions about it, and flagging that
# as host-root would be a false positive that teaches the reader to ignore the
# linter.
DEFAULT_CRITICAL_IF_WRITABLE = ("/etc/clixz", "/etc/systemd", "/etc/sudoers", "/etc/sudoers.d")


@dataclass(frozen=True)
class LintRules:
    levels: dict[str, str] = field(
        default_factory=lambda: {r.id: r.level for r in LINT_RULES})
    critical: tuple[str, ...] = DEFAULT_CRITICAL
    critical_if_writable: tuple[str, ...] = DEFAULT_CRITICAL_IF_WRITABLE

    def level(self, rule: str) -> str:
        return self.levels[rule]


@dataclass(frozen=True)
class Ignore:
    service: str            # "category/service"; fnmatch globs allowed
    rules: tuple[str, ...]
    reason: str

    def matches(self, service: str, rule: str) -> bool:
        return rule in self.rules and fnmatch.fnmatchcase(service, self.service)


@dataclass(frozen=True)
class Policy:
    lint: LintRules = field(default_factory=LintRules)
    ignores: tuple[Ignore, ...] = ()
    # Problems found in the two files. Reported by `clixz check`, never fatal:
    # a typo in ignore.yaml must not take the audit down with it.
    issues: tuple[str, ...] = ()
    lint_source: Path | None = None
    ignore_source: Path | None = None

    def ignored(self, service: str, rule: str) -> Ignore | None:
        for entry in self.ignores:
            if entry.matches(service, rule):
                return entry
        return None


# ─── loading ─────────────────────────────────────────────────────────────────

def _read(path: Path, issues: list[str]) -> dict | None:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        issues.append(f"{path.name}: cannot be read ({exc})")
        return None
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        issues.append(f"{path.name}: top-level YAML must be a mapping")
        return None
    return raw


def _path_list(raw: object, where: str, issues: list[str]) -> tuple[str, ...] | None:
    if not isinstance(raw, list) or not all(isinstance(p, str) and p.startswith("/") for p in raw):
        issues.append(f"{where} must be a list of absolute paths")
        return None
    return tuple(p.rstrip("/") or "/" for p in raw)


def parse_lint(raw: dict, issues: list[str], name: str = LINT_FILE) -> LintRules:
    levels = {r.id: r.level for r in LINT_RULES}
    rules = raw.get("rules") or {}
    if not isinstance(rules, dict):
        issues.append(f"{name}: 'rules' must be a mapping of rule id to level")
        rules = {}
    for rule, level in rules.items():
        # YAML 1.1 reads a bare `off` as the boolean false. Asking everyone to
        # quote it would be asking everyone to get it wrong once.
        if level is False:
            level = "off"
        if rule not in levels:
            issues.append(f"{name}: unknown rule '{rule}' (see `clixz rules`)")
        elif level not in LEVELS:
            issues.append(f"{name}: rules.{rule} is '{level}', expected one of "
                          f"{', '.join(LEVELS)}")
        else:
            levels[str(rule)] = str(level)

    critical, writable = DEFAULT_CRITICAL, DEFAULT_CRITICAL_IF_WRITABLE
    mounts = raw.get("mounts") or {}
    if not isinstance(mounts, dict):
        issues.append(f"{name}: 'mounts' must be a mapping")
        mounts = {}
    if "critical" in mounts:
        critical = _path_list(mounts["critical"], f"{name}: mounts.critical", issues) or critical
    if "critical_if_writable" in mounts:
        writable = _path_list(mounts["critical_if_writable"],
                              f"{name}: mounts.critical_if_writable", issues) or writable

    for key in raw:
        if key not in ("rules", "mounts"):
            issues.append(f"{name}: unknown top-level key '{key}'")
    return LintRules(levels=levels, critical=critical, critical_if_writable=writable)


def parse_ignores(raw: dict, issues: list[str], name: str = IGNORE_FILE) -> tuple[Ignore, ...]:
    entries = raw.get("ignore") or []
    if not isinstance(entries, list):
        issues.append(f"{name}: 'ignore' must be a list")
        return ()
    out: list[Ignore] = []
    for index, entry in enumerate(entries, start=1):
        where = f"{name}: entry {index}"
        if not isinstance(entry, dict):
            issues.append(f"{where} must be a mapping with service, rules and reason")
            continue
        service = entry.get("service")
        rules = entry.get("rules")
        reason = str(entry.get("reason") or "").strip()
        if not isinstance(service, str) or not service.strip():
            issues.append(f"{where} has no 'service'")
            continue
        if isinstance(rules, str):
            rules = [rules]
        if not isinstance(rules, list) or not rules:
            issues.append(f"{where} ({service}) has no 'rules'")
            continue
        unknown = [r for r in rules if r not in IGNORABLE_IDS]
        if unknown:
            issues.append(f"{where} ({service}) names unknown rule(s): "
                          f"{', '.join(map(str, unknown))} (see `clixz rules`)")
        # An exception nobody can justify is one nobody will dare remove, so an
        # entry without a reason is reported and not applied.
        if not reason:
            issues.append(f"{where} ({service}) has no 'reason' — not applied")
            continue
        known = tuple(str(r) for r in rules if r in IGNORABLE_IDS)
        if known:
            out.append(Ignore(service=service.strip(), rules=known, reason=reason))
    for key in raw:
        if key != "ignore":
            issues.append(f"{name}: unknown top-level key '{key}'")
    return tuple(out)


def load_policy(directory: Path | None) -> Policy:
    """Read ``lint.yaml`` and ``ignore.yaml`` from ``directory``, if they exist."""
    if directory is None:
        return Policy()
    issues: list[str] = []
    lint, ignores = LintRules(), ()
    lint_path, ignore_path = directory / LINT_FILE, directory / IGNORE_FILE
    lint_source = ignore_source = None
    if lint_path.is_file():
        lint_source = lint_path
        raw = _read(lint_path, issues)
        if raw is not None:
            lint = parse_lint(raw, issues)
    if ignore_path.is_file():
        ignore_source = ignore_path
        raw = _read(ignore_path, issues)
        if raw is not None:
            ignores = parse_ignores(raw, issues)
    return Policy(lint=lint, ignores=ignores, issues=tuple(issues),
                  lint_source=lint_source, ignore_source=ignore_source)


def template(name: str) -> str:
    """The commented starting file for ``lint.yaml`` or ``ignore.yaml``."""
    return files("clixz").joinpath(f"default_{name}").read_text(encoding="utf-8")
