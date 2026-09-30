"""Audit and repair of the service tree's ownership and modes.

The whole policy is three rules (``dir``, ``file``, ``env``) applied to a fixed
skeleton. Contents of ``config/`` and ``data/`` are never audited and never
touched: they belong to the service, and a recursive chown across a running
container's state directory is a good way to break it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .config import Config
from .system import CommandRunner, PathState, owner_ids, read_state

COMPOSE = "compose.yaml"
SERVICE_FILE = "service.yaml"
ENV_FILE = ".env"

# The directories every service has. Their contents are out of scope.
SERVICE_DIRS = ("config", "data")


class Severity(str, Enum):
    OK = "ok"
    WARN = "warn"
    ERROR = "error"


@dataclass
class Finding:
    path: Path
    severity: Severity
    message: str
    # Command that would fix it, or None when nothing can be done automatically.
    fix: list[str] | None = None
    # The id ignore.yaml refers to: missing-dir, missing-file, owner, mode, acl.
    rule: str = ""

    @property
    def fixable(self) -> bool:
        return self.fix is not None


@dataclass
class ServiceReport:
    category: str
    service: str
    path: Path
    findings: list[Finding] = field(default_factory=list)
    # Findings an ignore.yaml entry accepted, with the reason it gave. They
    # count for nothing: not in `worst`, not in `fixes`.
    ignored: list[tuple[Finding, str]] = field(default_factory=list)

    @property
    def name(self) -> str:
        return f"{self.category}/{self.service}"

    @property
    def worst(self) -> Severity:
        if any(f.severity is Severity.ERROR for f in self.findings):
            return Severity.ERROR
        if any(f.severity is Severity.WARN for f in self.findings):
            return Severity.WARN
        return Severity.OK

    @property
    def fixes(self) -> list[list[str]]:
        return [f.fix for f in self.findings if f.fix is not None]


# ─── discovery ───────────────────────────────────────────────────────────────

def is_excluded(config: Config, path: Path) -> bool:
    """True when ``path`` matches an ``exclude`` pattern or sits under one.

    "Under" is tested on a path boundary: excluding ``infra/komodo`` must not
    also exclude ``infra/komodo-periphery``.
    """
    text = str(path)
    for pattern in config.exclude:
        prefix = pattern.rstrip("*/")
        if fnmatch.fnmatch(text, pattern) or text == prefix or text.startswith(prefix + "/"):
            return True
    return False


def list_categories(config: Config) -> list[str]:
    """Categories declared in the config that exist on disk."""
    return sorted(
        name for name in config.categories
        if (config.root_dir / name).is_dir()
    )


def list_services(config: Config, category: str | None = None) -> list[tuple[str, str, Path]]:
    """Return ``(category, service, path)`` for every service directory."""
    out: list[tuple[str, str, Path]] = []
    for cat in ([category] if category else list_categories(config)):
        cat_dir = config.root_dir / cat
        if not cat_dir.is_dir():
            continue
        for entry in sorted(cat_dir.iterdir()):
            if entry.is_dir() and not entry.name.startswith(".") and not is_excluded(config, entry):
                out.append((cat, entry.name, entry))
    return out


def resolve_service(config: Config, name: str) -> tuple[str, str, Path]:
    """Resolve ``service`` or ``category/service`` to a concrete location.

    A bare name is looked up across categories; an ambiguous one is an error
    rather than a silent pick, because picking wrong means editing the wrong
    service's compose.
    """
    if "/" in name:
        category, _, service = name.partition("/")
        path = config.root_dir / category / service
        if category not in config.categories:
            raise KeyError(f"Unknown category '{category}'.")
        if not path.is_dir():
            raise KeyError(f"No such service: {category}/{service}")
        return category, service, path

    matches = [(c, s, p) for c, s, p in list_services(config) if s == name]
    if not matches:
        raise KeyError(f"No such service: {name}")
    if len(matches) > 1:
        found = ", ".join(f"{c}/{s}" for c, s, _ in matches)
        raise KeyError(f"Ambiguous service '{name}' — matches {found}. Qualify it.")
    return matches[0]


# ─── auditing ────────────────────────────────────────────────────────────────

def _audit_path(
    path: Path, rule_name: str, owner: str, config: Config, *, is_dir: bool,
) -> list[Finding]:
    rule = config.rule(rule_name)
    expected_owner = rule.owner or owner
    state: PathState = read_state(path)
    findings: list[Finding] = []

    if not state.exists:
        if is_dir:
            findings.append(Finding(
                path, Severity.ERROR, "directory is missing",
                fix=["mkdir", "-p", str(path)], rule="missing-dir",
            ))
        else:
            findings.append(Finding(path, Severity.WARN, "file is missing",
                                    rule="missing-file"))
        return findings

    if state.owner != expected_owner:
        if owner_ids(expected_owner) is None:
            findings.append(Finding(
                path, Severity.ERROR,
                f"owner is {state.owner}, expected {expected_owner} "
                "(which does not resolve on this host)", rule="owner",
            ))
        else:
            findings.append(Finding(
                path, Severity.ERROR,
                f"owner is {state.owner}, expected {expected_owner}",
                fix=["chown", expected_owner, str(path)], rule="owner",
            ))

    if state.mode != rule.mode:
        findings.append(Finding(
            path, Severity.ERROR,
            f"mode is {state.mode}, expected {rule.mode}",
            fix=["chmod", rule.mode, str(path)], rule="mode",
        ))

    if state.extended_acl:
        findings.append(Finding(
            path, Severity.WARN,
            "carries POSIX ACL entries — v2 uses owner/mode only (leftover from v1)",
            fix=["setfacl", "-b", str(path)], rule="acl",
        ))

    if not findings:
        findings.append(Finding(path, Severity.OK, f"{expected_owner} {rule.mode}"))
    return findings


def _apply_ignores(config: Config, report: ServiceReport) -> ServiceReport:
    """Move the findings ignore.yaml accepts out of the report proper."""
    kept: list[Finding] = []
    for finding in report.findings:
        entry = config.policy.ignored(report.name, finding.rule) if finding.rule else None
        if entry is None:
            kept.append(finding)
        else:
            report.ignored.append((finding, entry.reason))
    report.findings = kept
    return report


def audit_service(config: Config, category: str, service: str) -> ServiceReport:
    svc_path = config.root_dir / category / service
    report = ServiceReport(category=category, service=service, path=svc_path)
    owner = config.category(category).owner

    skeleton = [(svc_path, "dir", True)]
    skeleton += [(svc_path / name, "dir", True) for name in SERVICE_DIRS]
    skeleton += [(svc_path / COMPOSE, "file", False), (svc_path / SERVICE_FILE, "file", False),
                 (svc_path / ENV_FILE, "env", False)]
    for path, rule, is_dir in skeleton:
        # An excluded path is excluded from the audit *and* from the repair.
        # Until 2.2.1 only whole services were: `exclude: [infra/komodo/config]`
        # still had that directory chowned, chmodded and stripped of its ACL by
        # `clixz fix`, which locked Komodo Core out of its own keys.
        if is_excluded(config, path):
            continue
        report.findings += _audit_path(path, rule, owner, config, is_dir=is_dir)
    return _apply_ignores(config, report)


def audit_category_dir(config: Config, category: str) -> ServiceReport:
    """Audit the category directory itself (not its services)."""
    path = config.root_dir / category
    report = ServiceReport(category=category, service="", path=path)
    report.findings += _audit_path(
        path, "dir", config.category(category).owner, config, is_dir=True,
    )
    return _apply_ignores(config, report)


def audit_all(config: Config, category: str | None = None) -> list[ServiceReport]:
    reports: list[ServiceReport] = []
    for cat in ([category] if category else list_categories(config)):
        reports.append(audit_category_dir(config, cat))
        for c, service, _ in list_services(config, cat):
            reports.append(audit_service(config, c, service))
    return reports


def unknown_category_dirs(config: Config) -> list[Path]:
    """Directories under root_dir that no category declares.

    Reported, never removed: an undeclared directory is either a mistake in the
    config or a service nobody registered, and both want a human.
    """
    if not config.root_dir.is_dir():
        return []
    return sorted(
        p for p in config.root_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
        and p.name not in config.categories and not is_excluded(config, p)
    )


# ─── repair ──────────────────────────────────────────────────────────────────

# mkdir first (a chown on a missing path fails), then `setfacl -b`, then chown,
# then chmod.
#
# The setfacl position is the subtle one. On a path carrying an extended ACL,
# chmod writes the ACL *mask*, not the group bits — so `chmod 640` followed by
# `setfacl -b` leaves whatever g:: happened to hold, not 640. Stripping the ACL
# first turns the path back into an ordinary one, where chmod means what it
# says. v1 avoided the trap by never running chmod on an ACL-managed path; v2
# removes the ACLs instead, and this order is what makes that safe.
_ORDER = {"mkdir": 0, "setfacl": 1, "chown": 2, "chmod": 3}


def order_fixes(fixes: list[list[str]]) -> list[list[str]]:
    seen: set[tuple[str, ...]] = set()
    unique = []
    for fix in fixes:
        key = tuple(fix)
        if key not in seen:
            seen.add(key)
            unique.append(fix)
    return sorted(unique, key=lambda c: (_ORDER.get(c[0], 9), len(str(c[-1])), c[-1]))


@dataclass
class ApplyResult:
    executed: list[list[str]] = field(default_factory=list)
    failed: list[tuple[list[str], str]] = field(default_factory=list)


def apply_fixes(fixes: list[list[str]], *, dry_run: bool = False) -> ApplyResult:
    """Run every fix, continuing past failures so one bad path is not a wall."""
    from .system import CommandExecutionError

    runner = CommandRunner(dry_run=dry_run)
    result = ApplyResult()
    for command in order_fixes(fixes):
        try:
            runner.run(command)
            result.executed.append(command)
        except CommandExecutionError as exc:
            result.failed.append((command, exc.stderr.strip() or str(exc.returncode)))
    return result
