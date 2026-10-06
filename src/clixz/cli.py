"""clixz command line.

Verbs in six groups, which are also the panels of ``clixz --help``: inspect
(``ls``, ``show``, ``check``, ``exposed``, ``rules``), change (``new``,
``edit``, ``fix``, ``rm``, ``plan``, ``category``), publish (``meta``,
``manifest``), to do (``todo``), development (``image``, ``repo``), and clixz
itself (``config``, ``mcp``, ``daemon``, ``upgrade``).

Every write verb accepts ``--plan``: it prints what it would do, as JSON when
asked, and writes nothing. ``new`` and ``edit`` compute their plan with
``plans.compute`` — the same code that plans for the MCP server — so a change
the AI would be refused (an unaccepted lint error) is refused here too.
"""

from __future__ import annotations

import json as jsonlib
import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from . import compose as compose_mod
from . import daemon as daemon_mod
from . import mcpd as mcpd_mod
from . import npm as npm_mod
from . import plans as plans_mod
from . import repo as repo_mod
from . import rules as rules_mod
from .archive import archive_service, list_archived
from .category import add_category, plan_add
from .config import (
    Config,
    env,
    find_config_path,
    load_config,
    load_raw_config,
    migrate_raw,
    validate_config,
)
from .image import DOCKERFILE_NAME, dockerfile_template, validate_image_name
from .meta import (
    SERVICE_FILENAME,
    build_manifest,
    manifest_json,
    scaffold_template,
    write_manifest,
)
from .policy import (
    COMPOSE,
    Finding,
    Severity,
    apply_fixes,
    audit_all,
    audit_service,
    list_services,
    order_fixes,
    resolve_service,
    unknown_category_dirs,
)
from .system import CommandExecutionError, missing_bins
from .todo import OPEN_STATES, STATES, TodoError, TodoStore
from .upgrade import (
    UMASK,
    installed_version,
    latest_version,
    needs_root,
    plan_upgrade,
    run_upgrade,
)

app = typer.Typer(
    name="clixz",
    help="Inventory, check and create the Docker services under /srv/docker.",
    no_args_is_help=True,
    add_completion=True,
)
# The panels of `clixz --help`, in the order a command is declared in.
INSPECT = "Inspect — read-only"
CHANGE = "Change — need root, accept --plan"
PUBLISH = "Publish — service descriptors"
TODO = "To do — shared with the AI"
DEVELOP = "Development directories"
ITSELF = "clixz itself"

image_app = typer.Typer(help="Self-built image build contexts under /opt/images.",
                        no_args_is_help=True)
app.add_typer(image_app, name="image", rich_help_panel=DEVELOP)
repo_app = typer.Typer(help="Git checkouts under /opt/repos.", no_args_is_help=True)
app.add_typer(repo_app, name="repo", rich_help_panel=DEVELOP)
category_app = typer.Typer(help="Categories: a system account, a directory, a config entry.",
                           no_args_is_help=True)
app.add_typer(category_app, name="category", rich_help_panel=CHANGE)
plan_app = typer.Typer(help="Plans prepared through the MCP server, waiting to be applied.",
                       no_args_is_help=True)
app.add_typer(plan_app, name="plan", rich_help_panel=CHANGE)
todo_app = typer.Typer(help="What is left to do. The AI reads and writes the same list.",
                       no_args_is_help=True)
app.add_typer(todo_app, name="todo", rich_help_panel=TODO)
daemon_app = typer.Typer(help="clixz's own units: the MCP gateway and the root applier.",
                         no_args_is_help=True)
app.add_typer(daemon_app, name="daemon", rich_help_panel=ITSELF)

console = Console()
err = Console(stderr=True)


class Ctx:
    config: Config
    source: Optional[Path]


ctx = Ctx()

_SYMBOL = {Severity.OK: "✓", Severity.WARN: "!", Severity.ERROR: "✗"}
_STYLE = {Severity.OK: "green", Severity.WARN: "yellow", Severity.ERROR: "red"}
_LINT_STYLE = {"error": "red", "warn": "yellow", "info": "dim"}


# ─── plumbing ────────────────────────────────────────────────────────────────

def emit(payload: dict[str, Any]) -> None:
    """Print a machine-readable result and leave."""
    console.print_json(jsonlib.dumps(payload, ensure_ascii=False, default=str))


def ensure_root() -> None:
    """Re-exec through sudo when a write verb is run unprivileged.

    ``CLIXZ_NO_SUDO`` opts out — set by clixz-mcpd, which must never gain
    privilege, and useful in containers already running as root.
    """
    if os.geteuid() == 0:
        return
    if env("NO_SUDO"):
        err.print(
            "[red]ERROR[/red] This command needs root and CLIXZ_NO_SUDO is set."
        )
        raise typer.Exit(code=2)
    if shutil.which("sudo") is None:
        err.print("[red]ERROR[/red] This command needs root and sudo was not found.")
        raise typer.Exit(code=2)
    script = sys.argv[0]
    if not os.path.isabs(script):
        script = shutil.which(script) or os.path.abspath(script)
    console.print("[dim]Elevating with sudo…[/dim]")
    try:
        os.execvp("sudo", ["sudo", "--preserve-env=EDITOR",
                           sys.executable, script, *sys.argv[1:]])
    except OSError as exc:  # pragma: no cover
        err.print(f"[red]ERROR[/red] sudo failed: {exc}")
        raise typer.Exit(code=2)


def _lint(name: str, path: Path) -> tuple[list, list]:
    """Lint one service's compose: ``(findings, [(finding, reason), …] ignored)``."""
    policy = ctx.config.policy
    kept, ignored = [], []
    for finding in compose_mod.lint_compose(path / COMPOSE, path, policy.lint):
        entry = policy.ignored(name, finding.rule)
        if entry is None:
            kept.append(finding)
        else:
            ignored.append((finding, entry.reason))
    return kept, ignored


def _lint_json(finding) -> dict[str, str]:
    return {"service": finding.service, "level": finding.level,
            "rule": finding.rule, "message": finding.message}


def _resolve(name: str) -> tuple[str, str, Path]:
    try:
        return resolve_service(ctx.config, name)
    except KeyError as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)


def _complete_service(incomplete: str) -> list[str]:
    try:
        config, _ = load_config()
    except Exception:
        return []
    names = [f"{c}/{s}" for c, s, _ in list_services(config)]
    return [n for n in names if n.startswith(incomplete)]


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"clixz {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    config_file: Annotated[Optional[Path], typer.Option(
        "--config", "-c", help="Config file (default: /etc/clixz/config.yaml).")] = None,
    _version: Annotated[bool, typer.Option(
        "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit.")] = False,
) -> None:
    try:
        ctx.config, ctx.source = load_config(config_file)
    except (ValueError, FileNotFoundError, OSError) as exc:
        err.print(f"[red]ERROR[/red] Cannot load the config: {exc}")
        raise typer.Exit(code=2)


# ─── read ────────────────────────────────────────────────────────────────────

@app.command("ls", rich_help_panel=INSPECT)
def ls_cmd(
    category: Annotated[Optional[str], typer.Option("--category", "-C")] = None,
    archived: Annotated[bool, typer.Option("--archived", help="List archived services instead.")] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List services with their image and published ports."""
    if archived:
        rows = [
            {"category": c, "service": s, "archived_at": ts, "path": str(p)}
            for c, s, ts, p in list_archived(ctx.config)
        ]
        if json_out:
            return emit({"archived": rows})
        if not rows:
            console.print("[dim]Nothing archived.[/dim]")
            return
        table = Table(box=None, pad_edge=False)
        for column in ("CATEGORY", "SERVICE", "ARCHIVED"):
            table.add_column(column)
        for row in rows:
            table.add_row(row["category"], row["service"], row["archived_at"])
        console.print(table)
        return

    if category and category not in ctx.config.categories:
        err.print(f"[red]ERROR[/red] Unknown category '{category}'.")
        raise typer.Exit(code=2)

    rows = []
    for cat, service, path in list_services(ctx.config, category):
        image, ports, _ = compose_mod.summarize(path / COMPOSE)
        rows.append({
            "category": cat, "service": service, "path": str(path),
            "image": image, "ports": ports,
        })

    if json_out:
        return emit({"services": rows, "count": len(rows)})

    table = Table(box=None, pad_edge=False)
    for column in ("CATEGORY", "SERVICE", "IMAGE", "PORTS"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(row["category"], row["service"],
                      row["image"] or "[dim]—[/dim]",
                      ", ".join(row["ports"]) or "[dim]—[/dim]")
    console.print(table)
    console.print(f"\n[dim]{len(rows)} service(s).[/dim]")


@app.command("show", rich_help_panel=INSPECT)
def show_cmd(
    service: Annotated[str, typer.Argument(autocompletion=_complete_service)],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Everything clixz knows about one service."""
    category, name, path = _resolve(service)
    image, ports, containers = compose_mod.summarize(path / COMPOSE)
    report = audit_service(ctx.config, category, name)
    lint, lint_ignored = _lint(report.name, path)

    payload = {
        "category": category, "service": name, "path": str(path),
        "image": image, "ports": ports, "containers": containers,
        "owner": ctx.config.category(category).owner,
        "permissions": [
            {"path": str(f.path), "severity": f.severity.value, "rule": f.rule,
             "message": f.message}
            for f in report.findings
        ],
        "lint": [_lint_json(f) for f in lint],
        "ignored": _ignored_json(report, lint_ignored),
    }
    if json_out:
        return emit(payload)

    console.print(f"[bold]{category}/{name}[/bold]  [dim]{path}[/dim]")
    console.print(f"  image      {image or '—'}")
    console.print(f"  ports      {', '.join(ports) or '—'}")
    console.print(f"  containers {', '.join(containers) or '—'}")
    console.print(f"  owner      {ctx.config.category(category).owner}")

    console.print("\n[bold]Permissions[/bold]")
    for finding in report.findings:
        _print_finding(finding)

    console.print("\n[bold]Compose[/bold]")
    if not lint:
        console.print("  [green]✓[/green] nothing to report")
    for finding in lint:
        style = _LINT_STYLE[finding.level]
        prefix = f"{finding.service}: " if finding.service else ""
        console.print(
            f"  [{style}]{finding.level:5}[/{style}] {escape(prefix + finding.message)} "
            f"[dim]({finding.rule})[/dim]"
        )
    _print_ignored(report, lint_ignored)


def _ignored_json(report, lint_ignored: list) -> list[dict[str, str]]:
    return [
        {"rule": f.rule, "message": f.message, "path": str(f.path), "reason": reason}
        for f, reason in report.ignored
    ] + [
        {"rule": f.rule, "message": f.message, "service": f.service, "reason": reason}
        for f, reason in lint_ignored
    ]


def _print_ignored(report, lint_ignored: list) -> None:
    for finding, reason in [*report.ignored, *lint_ignored]:
        console.print(f"  [dim]ignored {escape(finding.message)} ({finding.rule}) — "
                      f"{escape(reason)}[/dim]")


def _print_finding(finding: Finding, indent: str = "  ") -> None:
    style = _STYLE[finding.severity]
    console.print(
        f"{indent}[{style}]{_SYMBOL[finding.severity]}[/{style}] "
        f"{escape(str(finding.path))} — {escape(finding.message)}"
    )


@app.command("check", rich_help_panel=INSPECT)
def check_cmd(
    service: Annotated[Optional[str], typer.Argument(autocompletion=_complete_service)] = None,
    category: Annotated[Optional[str], typer.Option("--category", "-C")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show OK findings too.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Audit permissions and lint every compose. Exits 1 on an error-level finding.

    Lint findings never change the exit code: they are advice about a file you
    own, not policy. Permission drift does — it is drift from a rule you set.
    """
    missing = missing_bins()
    if missing and not json_out:
        err.print(f"[yellow]![/yellow] missing binaries: {', '.join(missing)}")

    raw_issues: list[str] = []
    if ctx.source is not None:
        try:
            raw_issues = validate_config(load_raw_config(ctx.source))
        except (ValueError, OSError) as exc:
            raw_issues = [str(exc)]
    raw_issues += ctx.config.policy.issues

    if service:
        cat, name, _ = _resolve(service)
        reports = [audit_service(ctx.config, cat, name)]
    else:
        reports = audit_all(ctx.config, category)

    lint: dict[str, list] = {}
    lint_ignored: dict[str, list] = {}
    for report in reports:
        if report.service:
            lint[report.name], lint_ignored[report.name] = _lint(report.name, report.path)

    stray = unknown_category_dirs(ctx.config) if not service else []
    errors = sum(1 for r in reports for f in r.findings if f.severity is Severity.ERROR)
    warns = sum(1 for r in reports for f in r.findings if f.severity is Severity.WARN)
    # Counted per level: the closing line used to give permission warnings
    # only, next to a list full of compose warnings it did not count.
    lint_levels = {level: sum(1 for fs in lint.values() for f in fs if f.level == level)
                   for level in ("error", "warn", "info")}
    lint_errors = lint_levels["error"]
    ignored = (sum(len(r.ignored) for r in reports)
               + sum(len(fs) for fs in lint_ignored.values()))

    if json_out:
        emit({
            "config": {"source": str(ctx.source) if ctx.source else None, "issues": raw_issues},
            "services": [
                {
                    "name": r.name or r.category, "path": str(r.path),
                    "severity": r.worst.value,
                    "findings": [
                        {"path": str(f.path), "severity": f.severity.value,
                         "rule": f.rule, "message": f.message, "fix": f.fix}
                        for f in r.findings if verbose or f.severity is not Severity.OK
                    ],
                    "lint": [_lint_json(f) for f in lint.get(r.name, [])],
                    "ignored": _ignored_json(r, lint_ignored.get(r.name, [])),
                }
                for r in reports
            ],
            "unknown_directories": [str(p) for p in stray],
            "summary": {"errors": errors, "warnings": warns, "lint_errors": lint_errors,
                        "lint_warnings": lint_levels["warn"],
                        "lint_infos": lint_levels["info"], "ignored": ignored},
        })
        raise typer.Exit(code=1 if (errors or raw_issues) else 0)

    if raw_issues:
        console.print("[bold red]Config[/bold red]")
        for issue in raw_issues:
            console.print(f"  [red]✗[/red] {escape(issue)}")
        console.print()

    for report in reports:
        shown = [f for f in report.findings if verbose or f.severity is not Severity.OK]
        service_lint = lint.get(report.name, [])
        service_ignored = lint_ignored.get(report.name, [])
        has_ignored = verbose and (report.ignored or service_ignored)
        if not shown and not service_lint and not has_ignored:
            continue
        console.print(f"[bold]{report.name}[/bold]")
        for finding in shown:
            _print_finding(finding)
        for finding in service_lint:
            style = _LINT_STYLE[finding.level]
            prefix = f"{finding.service}: " if finding.service else ""
            console.print(
                f"  [{style}]{finding.level:5}[/{style}] {COMPOSE} — "
                f"{escape(prefix + finding.message)} [dim]({finding.rule})[/dim]"
            )
        if verbose:
            _print_ignored(report, service_ignored)

    for path in stray:
        console.print(f"[yellow]![/yellow] {path} is not a declared category")

    console.print(
        f"\n[dim]{len(reports)} target(s)[/dim]\n"
        f"[dim]  permissions  {errors} error(s), {warns} warning(s)[/dim]\n"
        f"[dim]  compose      {lint_errors} error(s), {lint_levels['warn']} warning(s), "
        f"{lint_levels['info']} info[/dim]"
        + (f"\n[dim]  ignored      {ignored}"
           + ("" if verbose else " (--verbose to list them)") + "[/dim]"
           if ignored else "")
    )
    if errors:
        console.print("[dim]Run `clixz fix` to repair the permission findings.[/dim]")
    if raw_issues:
        console.print("[dim]The config problems listed at the top are not fixed by "
                      "`clixz fix`: edit the file they name.[/dim]")
    raise typer.Exit(code=1 if (errors or raw_issues) else 0)


@app.command("exposed", rich_help_panel=INSPECT)
def exposed_cmd(
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Compare what the reverse proxy publishes against what the tree declares.

    The NPM database is root's: run unprivileged, the command goes through
    sudo. It is read at the moment of the question — there is no snapshot.
    """
    database = ctx.config.npm.database
    if database is not None and not os.access(database.parent, os.X_OK) and os.geteuid() != 0:
        ensure_root()
    payload = npm_mod.exposure_payload(ctx.config)
    if json_out:
        return emit(payload)
    if not payload["available"]:
        console.print(f"[yellow]![/yellow] {escape(payload['reason'])}")
        return

    table = Table(box=None, pad_edge=False)
    for column in ("DOMAIN", "TARGET", "ENABLED", "ACCESS LIST"):
        table.add_column(column, overflow="fold")
    for host in payload["hosts"]:
        table.add_row(
            ", ".join(host["domains"]), host["target"],
            "[green]yes[/green]" if host["enabled"] else "[dim]no[/dim]",
            "[dim]none[/dim]" if host["access_list_id"] == 0 else str(host["access_list_id"]),
        )
    console.print(table)

    if payload["findings"]:
        console.print()
        for finding in payload["findings"]:
            style = _LINT_STYLE[finding["level"]]
            console.print(f"[{style}]{finding['level']:5}[/{style}] {escape(finding['message'])}")
    summary = payload["summary"]
    console.print(f"\n[dim]{summary['total']} proxy host(s), {summary['enabled']} enabled.[/dim]")


@app.command("rules", rich_help_panel=INSPECT)
def rules_cmd(
    edit: Annotated[bool, typer.Option(
        "--edit", help="Open lint.yaml in $EDITOR (created from the defaults).")] = False,
    edit_ignore: Annotated[bool, typer.Option(
        "--edit-ignore", help="Open ignore.yaml in $EDITOR (created from a template).")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """The compose rules in effect, and the findings ignore.yaml accepts."""
    directory = ctx.config.config_dir
    if edit or edit_ignore:
        if directory is None:
            err.print("[red]ERROR[/red] No config file in use — the rule files live next "
                      "to it. Create one with `clixz config --edit` first.")
            raise typer.Exit(code=2)
        ensure_root()
        name = rules_mod.IGNORE_FILE if edit_ignore else rules_mod.LINT_FILE
        target = directory / name
        if not target.exists():
            target.write_text(rules_mod.template(name), encoding="utf-8")
            target.chmod(0o644)
        subprocess.run([os.environ.get("EDITOR", "nano"), str(target)], check=False)
        return

    policy = ctx.config.policy
    defaults = {r.id: r for r in rules_mod.LINT_RULES}
    payload = {
        "lint_file": str(policy.lint_source) if policy.lint_source else None,
        "ignore_file": str(policy.ignore_source) if policy.ignore_source else None,
        "rules": [
            {"id": rule, "level": policy.lint.level(rule), "default": spec.level,
             "summary": spec.summary}
            for rule, spec in defaults.items()
        ],
        "ignorable_only": [{"id": r.id, "summary": r.summary} for r in rules_mod.AUDIT_RULES],
        "mounts": {"critical": list(policy.lint.critical),
                   "critical_if_writable": list(policy.lint.critical_if_writable)},
        "ignore": [{"service": i.service, "rules": list(i.rules), "reason": i.reason}
                   for i in policy.ignores],
        "issues": list(policy.issues),
    }
    if json_out:
        return emit(payload)

    table = Table(box=None, pad_edge=False, title="Compose rules", title_justify="left")
    for column in ("RULE", "LEVEL", "WHAT IT FLAGS"):
        table.add_column(column)
    for row in payload["rules"]:
        level = row["level"]
        shown = f"[{_LINT_STYLE.get(level, 'dim')}]{level}[/]"
        if level != row["default"]:
            shown += f" [dim](default {row['default']})[/dim]"
        table.add_row(row["id"], shown, escape(row["summary"]))
    console.print(table)

    table = Table(box=None, pad_edge=False, title="Permission findings (ignorable only)",
                  title_justify="left")
    for column in ("RULE", "WHAT IT FLAGS"):
        table.add_column(column)
    for row in payload["ignorable_only"]:
        table.add_row(row["id"], escape(row["summary"]))
    console.print()
    console.print(table)

    console.print()
    console.print("[bold]Ignored[/bold]")
    if not policy.ignores:
        console.print("  [dim]nothing[/dim]")
    for entry in policy.ignores:
        console.print(f"  {escape(entry.service)}  {', '.join(entry.rules)}  "
                      f"[dim]— {escape(entry.reason)}[/dim]")

    console.print()
    fallback = "[dim]built-in defaults[/dim]"
    console.print(f"[bold]Rules[/bold]    {policy.lint_source or fallback}")
    console.print(f"[bold]Ignores[/bold]  {policy.ignore_source or '[dim]none[/dim]'}")
    for issue in policy.issues:
        console.print(f"[red]✗[/red] {escape(issue)}")
    console.print("[dim]`clixz rules --edit` changes a level; "
                  "`clixz rules --edit-ignore` accepts a finding.[/dim]")


# ─── write ───────────────────────────────────────────────────────────────────

def _render_plan(commands: list[list[str]], *, json_out: bool, action: str,
                 target: str) -> None:
    if json_out:
        return emit({"plan": True, "action": action, "target": target,
                     "commands": commands})
    console.print(f"[bold]Plan — {action} {target}[/bold]")
    for command in commands:
        console.print(f"  {' '.join(command)}")
    console.print(f"\n[dim]{len(commands)} command(s). Nothing written.[/dim]")


def _tree_needs_root() -> bool:
    """Whether writing the tree needs root: some category belongs to someone else."""
    if os.geteuid() == 0:
        return False
    me = pwd.getpwuid(os.getuid()).pw_name
    return any(cat.user != me for cat in ctx.config.categories.values())


def _read_input(value: Optional[str], what: str) -> Optional[str]:
    if value is None:
        return None
    try:
        return sys.stdin.read() if value == "-" else Path(value).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        err.print(f"[red]ERROR[/red] Cannot read the {what} from {value}: {exc}")
        raise typer.Exit(code=2)


def _diff_lines(diff: str) -> None:
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            console.print(f"[bold]{escape(line)}[/bold]")
        elif line.startswith("+"):
            console.print(f"[green]{escape(line)}[/green]")
        elif line.startswith("-"):
            console.print(f"[red]{escape(line)}[/red]")
        elif line.startswith("@@"):
            console.print(f"[cyan]{escape(line)}[/cyan]")
        else:
            console.print(escape(line))


def _show_plan(plan: plans_mod.Plan) -> None:
    title = f"Plan {plan.id} — " if plan.id else "Plan — "
    console.print(f"[bold]{title}{plan.action} {escape(plan.target)}[/bold]"
                  + (f"  [dim]{plan.status()}, from {plan.origin}, expires {plan.expires_at}[/dim]"
                     if plan.id else ""))
    for command in plan.commands:
        console.print(f"  {escape(' '.join(command))}")
    if plan.diff:
        console.print()
        _diff_lines(plan.diff)
    shown = [row for row in plan.lint if row["level"] != "info" or row["ignored"]]
    if shown:
        console.print("\n[bold]Compose[/bold]")
    for row in shown:
        style = _LINT_STYLE.get(row["level"], "dim")
        prefix = f"{row['service']}: " if row["service"] else ""
        note = f" [dim]— accepted: {escape(row['ignored'])}[/dim]" if row["ignored"] else ""
        console.print(f"  [{style}]{row['level']:5}[/{style}] {escape(prefix + row['message'])} "
                      f"[dim]({row['rule']})[/dim]{note}")
    for warning in plan.warnings:
        console.print(f"[yellow]![/yellow] {escape(warning)}")
    for reason in plan.blocked:
        console.print(f"[red]✗[/red] {escape(reason)}")


def _show_outcome(outcome: plans_mod.Outcome, *, json_out: bool, done: str) -> None:
    if json_out:
        emit(outcome.to_dict())
    else:
        if outcome.ok:
            console.print(f"[green]✓[/green] {done}")
        for command, error in outcome.failed:
            err.print(f"[red]✗[/red] {escape(' '.join(command))} — {escape(error)}")
        for note in outcome.notes:
            console.print(f"  {escape(note)}")
        for warning in outcome.warnings:
            console.print(f"[yellow]![/yellow] {escape(warning)}")
    if not outcome.ok:
        raise typer.Exit(code=1)


def _change(action: str, service: str, compose: Optional[str], service_file: Optional[str],
            stack: Optional[str], *, plan: bool, json_out: bool, yes: bool) -> None:
    """``new`` and ``edit``: compute the plan, show it, confirm, execute it."""
    if not plan and _tree_needs_root():
        # Before reading stdin: the sudo re-exec inherits it unread.
        ensure_root()
    raw: dict[str, Any] = {"action": action, "service": service,
                           "compose": _read_input(compose, "compose"),
                           "service_yaml": _read_input(service_file, "service.yaml")}
    if stack:
        raw["stack"] = stack
    try:
        computed = plans_mod.compute(ctx.config, plans_mod.Request.from_dict(raw))
    except plans_mod.PlanError as exc:
        if json_out:
            emit({"ok": False, "error": str(exc)})
            raise typer.Exit(code=2)
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)

    if plan or computed.blocked:
        if json_out:
            emit({"plan": True, **computed.to_dict()})
        else:
            _show_plan(computed)
            console.print("\n[dim]Nothing written.[/dim]")
        raise typer.Exit(code=1 if computed.blocked else 0)

    if not yes and not json_out:
        _show_plan(computed)
        if not typer.confirm("Apply?"):
            raise typer.Exit(code=1)
    outcome = plans_mod.execute(ctx.config, computed)
    verb = "Created" if action == "new" else "Updated"
    _show_outcome(outcome, json_out=json_out, done=f"{verb} {computed.target}.")
    if action == "new" and not json_out and outcome.ok:
        console.print(f"  Then `clixz check {computed.target}`.")


_COMPOSE_OPT = typer.Option("--compose", help="compose.yaml to write (- reads stdin).")
_SERVICE_OPT = typer.Option("--service-file", help="service.yaml to write (- reads stdin).")


@app.command("new", rich_help_panel=CHANGE)
def new_cmd(
    service: Annotated[str, typer.Argument(help="category/service")],
    compose: Annotated[Optional[str], _COMPOSE_OPT] = None,
    service_file: Annotated[Optional[str], _SERVICE_OPT] = None,
    stack: Annotated[Optional[str], typer.Option(
        "--stack", help="Komodo stack name (default: the service name).")] = None,
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Create a service: its tree, a compose (yours or the hardened template), its stack."""
    _change("new", service, compose, service_file, stack, plan=plan, json_out=json_out, yes=yes)


@app.command("edit", rich_help_panel=CHANGE)
def edit_cmd(
    service: Annotated[str, typer.Argument(autocompletion=_complete_service)],
    compose: Annotated[Optional[str], _COMPOSE_OPT] = None,
    service_file: Annotated[Optional[str], _SERVICE_OPT] = None,
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Replace a service's compose.yaml and/or service.yaml; the old ones are archived."""
    _change("edit", service, compose, service_file, None, plan=plan, json_out=json_out, yes=yes)


@app.command("fix", rich_help_panel=CHANGE)
def fix_cmd(
    service: Annotated[Optional[str], typer.Argument(autocompletion=_complete_service)] = None,
    category: Annotated[Optional[str], typer.Option("--category", "-C")] = None,
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Repair ownership and modes. Never touches config/ or data/ contents."""
    if service:
        cat, name, _ = _resolve(service)
        reports = [audit_service(ctx.config, cat, name)]
        target = f"{cat}/{name}"
    else:
        reports = audit_all(ctx.config, category)
        target = category or "all services"

    commands = order_fixes([f for r in reports for f in r.fixes])

    if plan:
        return _render_plan(commands, json_out=json_out, action="fix", target=target)

    if not commands:
        if json_out:
            return emit({"ok": True, "commands": [], "message": "nothing to fix"})
        console.print("[green]✓[/green] Nothing to fix.")
        return

    ensure_root()
    if not yes and not json_out:
        _render_plan(commands, json_out=False, action="fix", target=target)
        if not typer.confirm("Apply?"):
            raise typer.Exit(code=1)

    result = apply_fixes(commands)
    if json_out:
        return emit({
            "ok": not result.failed,
            "executed": result.executed,
            "failed": [{"command": c, "error": e} for c, e in result.failed],
        })
    console.print(f"[green]✓[/green] {len(result.executed)} command(s) applied.")
    for command, error in result.failed:
        err.print(f"[red]✗[/red] {' '.join(command)} — {error}")
    if result.failed:
        raise typer.Exit(code=1)


@app.command("rm", rich_help_panel=CHANGE)
def rm_cmd(
    service: Annotated[str, typer.Argument(autocompletion=_complete_service)],
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
    force: Annotated[bool, typer.Option(
        "--force", help="Delete outright instead of archiving. Irreversible.")] = False,
) -> None:
    """Archive a service under .archive/ (the default) or delete it (--force)."""
    category, name, path = _resolve(service)

    if force and (plan or json_out):
        # --force is the only destructive path in this CLI. Keeping it out of
        # the machine-readable surface is what makes it unreachable from mcpd.
        err.print("[red]ERROR[/red] --force is interactive only.")
        raise typer.Exit(code=2)

    if plan:
        return _render_plan(
            [["mv", str(path), str(ctx.config.root_dir / ".archive" / category / name / "<timestamp>")]],
            json_out=json_out, action="rm", target=f"{category}/{name}",
        )

    ensure_root()
    if not yes and not json_out:
        verb = "DELETE" if force else "archive"
        console.print(f"[bold]{verb}[/bold] {category}/{name} ({path})")
        if not typer.confirm(f"{verb} it?"):
            raise typer.Exit(code=1)

    try:
        result = archive_service(ctx.config, category, name, dry_run=False, force=force)
    except (CommandExecutionError, RuntimeError, OSError) as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1)

    if json_out:
        return emit({"ok": True, "archived_to": str(result.destination) if result.destination else None})
    if result.destination:
        console.print(f"[green]✓[/green] Archived to {result.destination}")
    else:
        console.print(f"[green]✓[/green] Deleted {path}")


# ─── housekeeping ────────────────────────────────────────────────────────────

@app.command("meta", rich_help_panel=PUBLISH)
def meta_cmd(
    service: Annotated[Optional[str], typer.Argument(autocompletion=_complete_service)] = None,
    scaffold: Annotated[bool, typer.Option(
        "--scaffold", help="Write a service.yaml template (never overwrites).")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate service descriptors, or scaffold a missing one."""
    if scaffold:
        if not service:
            err.print("[red]ERROR[/red] --scaffold needs a service.")
            raise typer.Exit(code=2)
        category, name, path = _resolve(service)
        target = path / SERVICE_FILENAME
        if target.exists():
            err.print(f"[red]ERROR[/red] {target} already exists.")
            raise typer.Exit(code=2)
        ensure_root()
        target.write_text(scaffold_template(category, name), encoding="utf-8")
        rule = ctx.config.rule("file")
        subprocess.run(["chown", rule.owner or ctx.config.category(category).owner,
                        str(target)], check=False)
        subprocess.run(["chmod", rule.mode, str(target)], check=False)
        console.print(f"[green]✓[/green] Wrote {target}")
        return

    result = build_manifest(ctx.config)
    if json_out:
        return emit({"errors": result.errors, "warnings": result.warnings,
                     "public": result.public_count, "private": result.private_count})
    for issue in result.errors:
        console.print(f"[red]✗[/red] {escape(issue)}")
    for issue in result.warnings:
        console.print(f"[yellow]![/yellow] {escape(issue)}")
    console.print(
        f"[dim]{result.public_count} public, {result.private_count} private, "
        f"{len(result.errors)} error(s).[/dim]"
    )
    raise typer.Exit(code=1 if result.errors else 0)


@app.command("manifest", rich_help_panel=PUBLISH)
def manifest_cmd(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Validate and preview only.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Aggregate the public service.yaml descriptors into the API manifest."""
    result = build_manifest(ctx.config)
    destination = ctx.config.resolved_manifest_path

    if result.errors:
        if json_out:
            emit({"ok": False, "errors": result.errors})
            raise typer.Exit(code=1)
        for issue in result.errors:
            err.print(f"[red]✗[/red] {issue}")
        raise typer.Exit(code=1)

    if dry_run:
        if json_out:
            return emit({"ok": True, "dry_run": True, "destination": str(destination),
                         "public": result.public_count, "warnings": result.warnings})
        console.print(manifest_json(result.manifest))
        console.print(f"[dim]Would write {destination}.[/dim]")
        return

    ensure_root()
    result = write_manifest(ctx.config)

    if json_out:
        return emit({"ok": True, "destination": str(destination),
                     "public": result.public_count})
    console.print(f"[green]✓[/green] Wrote {destination} "
                  f"({result.public_count} public service(s)).")


@image_app.command("add")
def image_add_cmd(name: str) -> None:
    """Scaffold an image build context under /opt/images/<name>/."""
    try:
        validate_image_name(name)
    except ValueError as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)
    target = ctx.config.images_dir / name
    if target.exists():
        err.print(f"[red]ERROR[/red] {target} already exists.")
        raise typer.Exit(code=2)
    target.mkdir(parents=True)
    (target / DOCKERFILE_NAME).write_text(dockerfile_template(name), encoding="utf-8")
    console.print(f"[green]✓[/green] Created {target}")


@image_app.command("rm")
def image_rm_cmd(
    name: str,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete an image build context."""
    target = ctx.config.images_dir / name
    if not target.is_dir():
        err.print(f"[red]ERROR[/red] No such image context: {target}")
        raise typer.Exit(code=2)
    if not yes and not typer.confirm(f"Delete {target}?"):
        raise typer.Exit(code=1)
    shutil.rmtree(target)
    console.print(f"[green]✓[/green] Deleted {target}")


@image_app.command("ls")
def image_ls_cmd(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """List image build contexts."""
    base = ctx.config.images_dir
    rows = []
    if base.is_dir():
        for entry in sorted(p for p in base.iterdir() if p.is_dir()):
            rows.append({"name": entry.name, "path": str(entry),
                         "dockerfile": (entry / DOCKERFILE_NAME).is_file()})
    if json_out:
        return emit({"images": rows, "dir": str(base)})
    if not rows:
        console.print(f"[dim]No image contexts under {base}.[/dim]")
        return
    table = Table(box=None, pad_edge=False)
    table.add_column("NAME")
    table.add_column("DOCKERFILE")
    for row in rows:
        table.add_row(row["name"], "yes" if row["dockerfile"] else "[red]missing[/red]")
    console.print(table)


@repo_app.command("add")
def repo_add_cmd(
    name: str,
    url: Annotated[Optional[str], typer.Option(
        "--url", help="Clone this remote instead of creating an empty repository.")] = None,
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create /opt/repos/<name>: an empty git repository, or a clone of --url."""
    try:
        commands = repo_mod.plan_add(ctx.config.repos_dir, name, url)
    except ValueError as exc:
        if json_out:
            emit({"ok": False, "error": str(exc)})
            raise typer.Exit(code=2)
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)
    if plan:
        return _render_plan(commands, json_out=json_out, action="repo add", target=name)
    for command in commands:
        done = subprocess.run(command, check=False)
        if done.returncode != 0:
            err.print(f"[red]ERROR[/red] {' '.join(command)} exited {done.returncode}.")
            raise typer.Exit(code=1)
    if json_out:
        return emit({"ok": True, "created": str(ctx.config.repos_dir / name)})
    console.print(f"[green]✓[/green] Created {ctx.config.repos_dir / name}")


@repo_app.command("rm")
def repo_rm_cmd(
    name: str,
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete a checkout. Whatever was not pushed is gone with it."""
    try:
        repo_mod.validate_repo_name(name)
    except ValueError as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)
    target = ctx.config.repos_dir / name
    if not target.is_dir():
        if json_out:
            emit({"ok": False, "error": f"No such repo: {target}"})
            raise typer.Exit(code=2)
        err.print(f"[red]ERROR[/red] No such repo: {target}")
        raise typer.Exit(code=2)
    if plan:
        return _render_plan([["rm", "-rf", str(target)]], json_out=json_out,
                            action="repo rm", target=name)
    if json_out:
        # Same reasoning as `rm --force`: a deletion is never reachable from the
        # machine-readable surface, only planned there.
        err.print("[red]ERROR[/red] `repo rm` is interactive only; use --plan with --json.")
        raise typer.Exit(code=2)
    if not yes and not typer.confirm(
            f"Delete {target}? Commits that were not pushed are lost."):
        raise typer.Exit(code=1)
    shutil.rmtree(target)
    console.print(f"[green]✓[/green] Deleted {target}")


@repo_app.command("ls")
def repo_ls_cmd(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """List the checkouts with their branch and remote."""
    base = ctx.config.repos_dir
    rows = repo_mod.list_repos(base)
    if json_out:
        return emit({"repos": rows, "dir": str(base)})
    if not rows:
        console.print(f"[dim]No repos under {base}.[/dim]")
        return
    table = Table(box=None, pad_edge=False)
    for column in ("NAME", "BRANCH", "REMOTE"):
        table.add_column(column, overflow="fold")
    for row in rows:
        if not row["git"]:
            table.add_row(row["name"], "[dim]not a git repository[/dim]", "")
            continue
        table.add_row(row["name"], row.get("branch") or "[dim]—[/dim]",
                      row.get("remote") or "[dim]no origin[/dim]")
    console.print(table)


@category_app.command("add")
def category_add_cmd(
    name: str,
    account: Annotated[Optional[str], typer.Option(
        "--account", help="System user and group to own it (default: svc_<name>).")] = None,
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Create a category: its system account, its directory, its config entry."""
    try:
        planned = plan_add(ctx.config, ctx.source, name, account)
    except (ValueError, OSError) as exc:
        if json_out:
            emit({"ok": False, "error": str(exc)})
            raise typer.Exit(code=2)
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)

    if plan:
        if json_out:
            return emit({"plan": True, "action": "category add", "target": name,
                         "commands": planned.commands, "next_steps": planned.notes})
        _render_plan(planned.commands, json_out=False, action="category add", target=name)
        for note in planned.notes:
            console.print(f"[dim]then: {escape(note)}[/dim]")
        return

    ensure_root()
    if not yes and not json_out:
        _render_plan(planned.commands, json_out=False, action="category add", target=name)
        if not typer.confirm("Create it?"):
            raise typer.Exit(code=1)
    try:
        done = add_category(ctx.config, ctx.source, name, account)
    except (CommandExecutionError, ValueError, OSError) as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1)
    if json_out:
        return emit({"ok": True, "created": name, "commands": done.commands,
                     "next_steps": done.notes})
    console.print(f"[green]✓[/green] Created category {name}.")
    for note in done.notes:
        console.print(f"  [yellow]![/yellow] {escape(note)}")


@category_app.command("ls")
def category_ls_cmd(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """List the categories with their account and how many services they hold."""
    rows = [
        {"name": name, "owner": cat.owner,
         "exists": (ctx.config.root_dir / name).is_dir(),
         "services": len(list_services(ctx.config, name))}
        for name, cat in sorted(ctx.config.categories.items())
    ]
    if json_out:
        return emit({"categories": rows})
    table = Table(box=None, pad_edge=False)
    for column in ("CATEGORY", "OWNER", "SERVICES"):
        table.add_column(column)
    for row in rows:
        table.add_row(row["name"], row["owner"],
                      str(row["services"]) if row["exists"] else "[red]no directory[/red]")
    console.print(table)


# ─── plans ───────────────────────────────────────────────────────────────────

def _plans_access(write: bool) -> None:
    directory = ctx.config.state.plans_dir
    mode = os.R_OK | os.X_OK | (os.W_OK if write else 0)
    if directory.exists() and not os.access(directory, mode):
        ensure_root()


def _plan_or_exit(plan_id: str) -> plans_mod.Plan:
    try:
        return plans_mod.load(ctx.config, plan_id)
    except plans_mod.PlanError as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)


@plan_app.command("ls")
def plan_ls_cmd(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """The stored plans: pending, and expired within the last day."""
    _plans_access(write=False)
    found = plans_mod.list_plans(ctx.config)
    if json_out:
        return emit({"plans": [p.summary() for p in found]})
    if not found:
        console.print("[dim]No plan waiting.[/dim]")
        return
    table = Table(box=None, pad_edge=False)
    for column in ("ID", "ACTION", "TARGET", "STATUS", "FROM", "EXPIRES"):
        table.add_column(column)
    for plan in found:
        status = plan.status()
        table.add_row(plan.id or "", plan.action, plan.target,
                      f"[dim]{status}[/dim]" if status == "expired" else status,
                      plan.origin, plan.expires_at or "")
    console.print(table)


@plan_app.command("show")
def plan_show_cmd(
    plan_id: str,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """One plan: its commands, its diff, the compose lint."""
    _plans_access(write=False)
    plan = _plan_or_exit(plan_id)
    if json_out:
        return emit(plan.to_dict())
    _show_plan(plan)


@plan_app.command("apply")
def plan_apply_cmd(
    plan_id: str,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Apply a stored plan — once, and only if the disk still matches it."""
    _plans_access(write=True)
    plan = _plan_or_exit(plan_id)
    if not yes and not json_out:
        _show_plan(plan)
        if not typer.confirm("Apply?"):
            raise typer.Exit(code=1)
    if _tree_needs_root():
        ensure_root()
    try:
        outcome = plans_mod.apply(ctx.config, plan_id)
    except plans_mod.PlanError as exc:
        if json_out:
            emit({"ok": False, "error": str(exc)})
            raise typer.Exit(code=1)
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1)
    _show_outcome(outcome, json_out=json_out, done=f"Applied {plan_id}: {plan.action} {plan.target}.")


@plan_app.command("drop")
def plan_drop_cmd(plan_id: str) -> None:
    """Delete a stored plan without applying it."""
    _plans_access(write=True)
    try:
        plan = plans_mod.drop(ctx.config, plan_id)
    except plans_mod.PlanError as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(f"[green]✓[/green] Dropped {plan_id} ({plan.action} {escape(plan.target)}).")


# ─── todo ────────────────────────────────────────────────────────────────────

_STATE_LABEL = {"todo": "to do", "doing": "[yellow]doing[/yellow]",
                "done": "[green]done[/green]", "archived": "[dim]archived[/dim]"}


def _todo() -> TodoStore:
    return TodoStore(ctx.config.state.todo_file, group=ctx.config.state.group)


def _todo_call(action, json_out: bool = False):
    """Run a todo operation; on a permission problem, retry through sudo."""
    try:
        return action()
    except TodoError as exc:
        if json_out:
            emit({"ok": False, "error": str(exc)})
        else:
            err.print(f"[red]ERROR[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)
    except PermissionError:
        if os.geteuid() != 0:
            err.print(f"[dim]{ctx.config.state.todo_file} is not writable by you "
                      f"(members of {ctx.config.state.group} can) — going through sudo.[/dim]")
            ensure_root()
        raise


def _print_item(item) -> None:
    console.print(f"[bold]#{item.id} {escape(item.title)}[/bold]  {_STATE_LABEL[item.state]}")
    console.print(f"[dim]created {item.created}, updated {item.updated}[/dim]")
    if item.description:
        console.print()
        console.print(escape(item.description))


@todo_app.command("ls")
def todo_ls_cmd(
    state: Annotated[Optional[list[str]], typer.Option(
        "--state", help=f"Only these states ({', '.join(STATES)}); repeatable.")] = None,
    all_states: Annotated[bool, typer.Option("--all", help="Every state, archived included.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """What is left to do (to do and doing, unless asked otherwise)."""
    wanted = STATES if all_states else tuple(state or OPEN_STATES)
    for name in wanted:
        if name not in STATES:
            err.print(f"[red]ERROR[/red] Unknown state '{name}' (known: {', '.join(STATES)}).")
            raise typer.Exit(code=2)
    items = [i for i in _todo_call(_todo().items, json_out) if i.state in wanted]
    if json_out:
        return emit({"items": [i.to_dict() for i in items], "count": len(items),
                     "file": str(ctx.config.state.todo_file)})
    if not items:
        console.print("[dim]Nothing to do.[/dim]")
        return
    table = Table(box=None, pad_edge=False)
    for column in ("#", "STATE", "TITLE"):
        table.add_column(column)
    for item in items:
        table.add_row(str(item.id), _STATE_LABEL[item.state], escape(item.title))
    console.print(table)


@todo_app.command("add")
def todo_add_cmd(
    title: str,
    description: Annotated[str, typer.Option("--description", "-d")] = "",
    state: Annotated[str, typer.Option("--state")] = "todo",
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Add an item."""
    item = _todo_call(lambda: _todo().add(title, description, state), json_out)
    if json_out:
        return emit(item.to_dict())
    console.print(f"[green]✓[/green] #{item.id} {escape(item.title)}")


@todo_app.command("show")
def todo_show_cmd(item_id: int, json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """One item, with its description."""
    item = _todo_call(lambda: _todo().get(item_id), json_out)
    if json_out:
        return emit(item.to_dict())
    _print_item(item)


def _edit_in_editor(item) -> dict[str, str]:
    import tempfile

    import yaml

    text = yaml.safe_dump({"title": item.title, "state": item.state,
                           "description": item.description}, sort_keys=False, allow_unicode=True)
    with tempfile.NamedTemporaryFile("w+", suffix=".yaml", encoding="utf-8") as f:
        f.write(f"# todo #{item.id} — states: {', '.join(STATES)}\n{text}")
        f.flush()
        subprocess.run([os.environ.get("EDITOR", "nano"), f.name], check=False)
        f.seek(0)
        try:
            edited = yaml.safe_load(f.read())
        except yaml.YAMLError as exc:
            err.print(f"[red]ERROR[/red] Not valid YAML, nothing changed: {exc}")
            raise typer.Exit(code=2)
    if not isinstance(edited, dict):
        err.print("[red]ERROR[/red] Expected title, state and description; nothing changed.")
        raise typer.Exit(code=2)
    return {k: str(edited[k]) for k in ("title", "state", "description") if edited.get(k) is not None}


@todo_app.command("edit")
def todo_edit_cmd(
    item_id: int,
    title: Annotated[Optional[str], typer.Option("--title")] = None,
    description: Annotated[Optional[str], typer.Option("--description", "-d")] = None,
    state: Annotated[Optional[str], typer.Option("--state")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Change an item. Without an option, open it in $EDITOR."""
    store = _todo()
    if title is None and description is None and state is None:
        changes = _edit_in_editor(_todo_call(lambda: store.get(item_id), json_out))
    else:
        changes = {k: v for k, v in (("title", title), ("description", description),
                                     ("state", state)) if v is not None}
    item = _todo_call(lambda: store.update(item_id, **changes), json_out)
    if json_out:
        return emit(item.to_dict())
    console.print(f"[green]✓[/green] #{item.id} {escape(item.title)}  {_STATE_LABEL[item.state]}")


def _set_state(item_id: int, state: str) -> None:
    item = _todo_call(lambda: _todo().update(item_id, state=state))
    console.print(f"[green]✓[/green] #{item.id} {escape(item.title)}  {_STATE_LABEL[item.state]}")


@todo_app.command("start")
def todo_start_cmd(item_id: int) -> None:
    """Mark an item as in progress."""
    _set_state(item_id, "doing")


@todo_app.command("done")
def todo_done_cmd(item_id: int) -> None:
    """Mark an item as done."""
    _set_state(item_id, "done")


@todo_app.command("archive")
def todo_archive_cmd(item_id: int) -> None:
    """Archive an item: kept, but out of every listing but --all."""
    _set_state(item_id, "archived")


@todo_app.command("rm")
def todo_rm_cmd(
    item_id: int,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Delete an item for good (archive keeps it)."""
    store = _todo()
    item = _todo_call(lambda: store.get(item_id), json_out)
    if not yes and not json_out and not typer.confirm(f"Delete #{item.id} {item.title}?"):
        raise typer.Exit(code=1)
    removed = _todo_call(lambda: store.remove(item_id), json_out)
    if json_out:
        return emit({"ok": True, "removed": removed.to_dict()})
    console.print(f"[green]✓[/green] Deleted #{removed.id} {escape(removed.title)}")


# ─── daemon ──────────────────────────────────────────────────────────────────

@daemon_app.command("install")
def daemon_install_cmd(
    plan: Annotated[bool, typer.Option("--plan", help="Print what would run, run nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Write the units this version ships, and (re)start what needs it."""
    if plan:
        commands = daemon_mod.install(ctx.config, dry_run=True)
        return _render_plan(commands, json_out=json_out, action="daemon install",
                            target=str(daemon_mod.UNIT_DIR))
    ensure_root()
    try:
        commands = daemon_mod.install(ctx.config)
    except (CommandExecutionError, OSError) as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1)
    if json_out:
        return emit({"ok": True, "commands": commands})
    for command in commands:
        console.print(f"  {escape(' '.join(command))}")
    console.print(f"[green]✓[/green] clixz {__version__}: units in place.")


@daemon_app.command("status")
def daemon_status_cmd(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Whether the installed units match this version, and whether they run."""
    payload = daemon_mod.status(ctx.config)
    payload["version"] = __version__
    if json_out:
        return emit(payload)
    table = Table(box=None, pad_edge=False)
    for column in ("UNIT", "FILE", "RUNNING"):
        table.add_column(column)
    state_label = {"ok": "[green]up to date[/green]", "missing": "[red]not installed[/red]",
                   "differs": "[yellow]differs from the package[/yellow]"}
    for unit in payload["units"]:
        running = {True: "[green]yes[/green]", False: "[red]no[/red]", None: "[dim]—[/dim]"}
        table.add_row(unit["name"], state_label[unit["state"]], running[unit["active"]])
    console.print(table)
    if payload["mcpd_stale"]:
        console.print("[yellow]![/yellow] clixz-mcpd started before this version was installed: "
                      "`sudo clixz daemon restart`")
    for name in payload["retired_present"]:
        console.print(f"[yellow]![/yellow] {name} is from an earlier version: "
                      "`sudo clixz daemon install` removes it")
    if any(u["state"] != "ok" for u in payload["units"]):
        console.print("[dim]`sudo clixz daemon install` brings them in line.[/dim]")


@daemon_app.command("restart")
def daemon_restart_cmd() -> None:
    """Restart clixz-mcpd (clixz-apply needs none: one process per request)."""
    ensure_root()
    done = subprocess.run(["systemctl", "restart", daemon_mod.MCPD_UNIT], check=False)
    if done.returncode != 0:
        raise typer.Exit(code=done.returncode)
    console.print(f"[green]✓[/green] Restarted {daemon_mod.MCPD_UNIT}.")


@app.command("config", rich_help_panel=ITSELF)
def config_cmd(
    edit: Annotated[bool, typer.Option("--edit", help="Open the config in $EDITOR.")] = False,
    migrate: Annotated[bool, typer.Option(
        "--migrate", help="Print a v2 config translated from the current v1 one.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show, migrate or edit the resolved configuration."""
    import yaml

    if migrate:
        raw = load_raw_config(ctx.source)
        console.print(yaml.safe_dump(migrate_raw(raw), sort_keys=False, allow_unicode=True))
        console.print(
            f"[dim]Review, then write it to "
            f"{find_config_path() or '/etc/clixz/config.yaml'}.[/dim]"
        )
        return

    if edit:
        ensure_root()
        target = ctx.source or Path("/etc/clixz/config.yaml")
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            from importlib.resources import files
            target.write_text(
                files("clixz").joinpath("default_config.yaml").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        editor = os.environ.get("EDITOR", "nano")
        subprocess.run([editor, str(target)], check=False)
        return

    config = ctx.config
    issues = validate_config(load_raw_config(ctx.source)) if ctx.source else []
    payload = {
        "source": str(ctx.source) if ctx.source else "bundled default",
        "root_dir": str(config.root_dir),
        "categories": {n: c.owner for n, c in sorted(config.categories.items())},
        "rules": {n: {"mode": r.mode, "owner": r.owner} for n, r in config.rules.items()},
        "exclude": config.exclude,
        "manifest": str(config.resolved_manifest_path),
        "images_dir": str(config.images_dir),
        "repos_dir": str(config.repos_dir),
        "lint_file": str(config.policy.lint_source) if config.policy.lint_source else None,
        "ignore_file": str(config.policy.ignore_source) if config.policy.ignore_source else None,
        "npm_database": str(config.npm.database) if config.npm.database else None,
        "issues": issues,
    }
    if json_out:
        return emit(payload)

    console.print(f"[bold]Source[/bold]     {payload['source']}")
    console.print(f"[bold]Root[/bold]       {payload['root_dir']}")
    console.print(f"[bold]Manifest[/bold]   {payload['manifest']}")
    console.print(f"[bold]Images[/bold]     {payload['images_dir']}")
    console.print(f"[bold]Repos[/bold]      {payload['repos_dir']}")
    console.print(f"[bold]Rules[/bold]      {payload['lint_file'] or 'built-in defaults'}")
    console.print(f"[bold]Ignores[/bold]    {payload['ignore_file'] or '—'}")
    console.print(f"[bold]NPM db[/bold]     {payload['npm_database'] or '—'}")

    table = Table(box=None, pad_edge=False, title="Categories", title_justify="left")
    table.add_column("CATEGORY")
    table.add_column("OWNER")
    for name, owner in payload["categories"].items():
        table.add_row(name, owner)
    console.print()
    console.print(table)

    table = Table(box=None, pad_edge=False, title="Rules", title_justify="left")
    for column in ("RULE", "MODE", "OWNER"):
        table.add_column(column)
    for name, rule in payload["rules"].items():
        table.add_row(name, rule["mode"], rule["owner"] or "[dim]category[/dim]")
    console.print()
    console.print(table)

    if issues:
        console.print()
        for issue in issues:
            console.print(f"[red]✗[/red] {escape(issue)}")
        console.print("[dim]Run `clixz config --migrate` for a v2 translation.[/dim]")


MCPD_UNIT_FILE = daemon_mod.UNIT_DIR / daemon_mod.MCPD_UNIT

# What stays out of reach whatever the caller sends. Not derived from code: it
# is the list of things a reader would otherwise have to infer from an absence.
MCP_NEVER = (
    "rm --force and repo rm, the two destructive paths: they refuse --plan and --json",
    "applying a category or repo plan: only service plans (new, edit, fix, rm) are applied",
    "a plan with an error-level lint finding that ignore.yaml does not accept: refused",
    "writing the config, lint.yaml, ignore.yaml or the units: outside clixz-apply's sandbox",
    "the contents of .env files: never read; `new` creates an empty one, Komodo fills it",
    "deploying: a new service's stack is created in Komodo, never deployed",
    "config --edit, rules --edit, meta --scaffold, image add/rm, upgrade, daemon install",
)


def _unit_setting(text: str, key: str) -> list[str]:
    values: list[str] = []
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() == key:
            values += value.split()
    return values


@app.command("mcp", rich_help_panel=ITSELF)
def mcp_cmd(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """What the MCP gateway (clixz-mcpd) runs, relays to clixz-apply, and never does."""
    payload: dict[str, Any] = mcpd_mod.access()
    payload["never"] = list(MCP_NEVER)
    socket_path = Path(payload["socket"])
    # The runtime directory is 0750: from another account "absent" and "not
    # allowed to look" are the same stat() failure, and only one of them is news.
    payload["socket_present"] = (
        socket_path.exists() if os.access(socket_path.parent, os.X_OK) else None)

    try:
        unit = MCPD_UNIT_FILE.read_text(encoding="utf-8")
    except OSError:
        unit = None
    payload["unit"] = str(MCPD_UNIT_FILE) if unit is not None else None
    account = (_unit_setting(unit, "User") or [None])[0] if unit is not None else None
    groups = set(_unit_setting(unit, "SupplementaryGroups")) if unit is not None else set()
    if account:
        groups.add(account)
    payload["account"] = account
    # A category is readable when the daemon carries its group: every
    # directory of the tree is owner+group only.
    payload["categories"] = [
        {"name": name, "group": cat.group,
         "readable": (cat.group in groups) if unit is not None else None}
        for name, cat in sorted(ctx.config.categories.items())
    ]
    if json_out:
        return emit(payload)

    state = {True: "[green]present[/green]", False: "[red]absent[/red]",
             None: "[dim]not visible from this account — try with sudo[/dim]"}[
                 payload["socket_present"]]
    console.print(f"[bold]Socket[/bold]   {payload['socket']}  {state}")
    unit_label = payload["unit"] or "[red]not installed[/red]"
    console.print(f"[bold]Unit[/bold]     {unit_label}")
    console.print(f"[bold]Account[/bold]  {account or '[dim]unknown[/dim]'}")

    for title, key, column, field in (
            ("Reads — the CLI, unprivileged", "read", "RUNS", "runs"),
            ("Planned only — never applied", "plan", "RUNS", "runs"),
            ("Relayed to clixz-apply (root, one process per request)", "relay", "DOES", "does")):
        table = Table(box=None, pad_edge=False, title=title, title_justify="left")
        table.add_column("REQUEST")
        table.add_column(column)
        for row in payload[key]:
            table.add_row(row["request"], escape(row[field]))
        console.print()
        console.print(table)

    table = Table(box=None, pad_edge=False, title="Tree it can read", title_justify="left")
    for column in ("CATEGORY", "GROUP", "READABLE"):
        table.add_column(column)
    for row in payload["categories"]:
        readable = {True: "[green]yes[/green]", False: "[red]no — not in the unit's groups[/red]",
                    None: "[dim]unknown[/dim]"}[row["readable"]]
        table.add_row(row["name"], row["group"], readable)
    console.print()
    console.print(table)

    console.print()
    console.print("[bold]Never reachable[/bold]")
    for line in MCP_NEVER:
        console.print(f"  • {escape(line)}")
    console.print("\n[dim]The tools the MCP server builds on these requests are defined "
                  "in its own image, not here.[/dim]")


def _launcher() -> str:
    script = sys.argv[0]
    if not os.path.isabs(script):
        script = shutil.which(script) or os.path.abspath(script)
    return script


@app.command("upgrade", rich_help_panel=ITSELF)
def upgrade_cmd(
    plan: Annotated[bool, typer.Option(
        "--plan", help="Print the commands that would run, and run nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Upgrade clixz to the latest release, without cache, then its units."""
    prefix = Path(sys.prefix)
    upgrade = plan_upgrade(prefix, Path(sys.argv[0]))
    if upgrade is None:
        err.print(f"[red]ERROR[/red] {prefix} was installed by neither pipx nor uv; "
                  "upgrade it the way it was installed.")
        raise typer.Exit(code=2)
    units_installed = (daemon_mod.UNIT_DIR / daemon_mod.MCPD_UNIT).exists()
    latest = latest_version()

    if plan:
        assignments = [f"{key}={value}" for key, value in upgrade.env.items()]
        commands = [[*assignments, *upgrade.argv]]
        if units_installed:
            commands.append(["clixz", "daemon", "install", "# the new version's"])
        if json_out:
            return emit({"plan": True, "action": "upgrade", "target": str(prefix),
                         "installed": __version__, "latest": latest, "commands": commands})
        console.print(f"[dim]installed {__version__}, PyPI {latest or 'unreachable'}[/dim]")
        return _render_plan(commands, json_out=False, action="upgrade", target=str(prefix))

    if latest is not None and latest == __version__:
        console.print(f"[green]✓[/green] clixz {__version__} is the latest release.")
        return
    if shutil.which(upgrade.argv[0]) is None:
        err.print(f"[red]ERROR[/red] {upgrade.argv[0]} installed clixz but was not found on PATH.")
        raise typer.Exit(code=2)
    if needs_root(prefix):
        ensure_root()
    # On a host with UMASK 027 the installer would leave the venv unreadable
    # to the unprivileged daemon: see upgrade.py.
    os.umask(UMASK)
    if latest:
        console.print(f"[dim]PyPI publishes {latest}; installing it without cache…[/dim]")

    def run() -> int:
        try:
            return subprocess.run(upgrade.argv, env={**os.environ, **upgrade.env},
                                  check=False).returncode
        except OSError as exc:  # pragma: no cover
            err.print(f"[red]ERROR[/red] {upgrade.argv[0]} failed: {exc}")
            return 2

    def wait(delay: float) -> None:
        console.print(f"[dim]PyPI does not serve {latest} to the installer yet; "
                      f"trying again in {delay:.0f}s…[/dim]")
        time.sleep(delay)

    code, after = run_upgrade(run, latest, sleep=wait,
                              version_after=lambda: installed_version(sys.executable))
    if code != 0:
        raise typer.Exit(code=code)
    if latest is not None and after != latest:
        err.print(f"[red]✗[/red] {latest} is published, but {after or 'an unknown version'} is "
                  "what got installed. Try again in a minute.")
        raise typer.Exit(code=1)
    if after is None or after == __version__:
        console.print(f"[green]✓[/green] clixz {__version__}: nothing newer was installed.")
        return
    console.print(f"[green]✓[/green] clixz {__version__} → {after}")
    if not units_installed:
        return
    if os.geteuid() != 0:
        console.print("[yellow]![/yellow] Now `sudo clixz daemon install`: the units and the "
                      "gateway still run the previous version.")
        return
    # The new binary, not this process: it imported the old code.
    done = subprocess.run([_launcher(), "daemon", "install"], check=False)
    if done.returncode != 0:
        err.print("[red]✗[/red] `clixz daemon install` failed — run it again with sudo.")
        raise typer.Exit(code=1)


def cli_main() -> None:  # pragma: no cover
    app()
