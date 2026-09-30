"""clixz command line.

Ten verbs, in three groups: read (``ls``, ``show``, ``check``, ``exposed``),
write (``new``, ``fix``, ``rm``), and housekeeping (``meta``, ``manifest``,
``image``, ``config``).

Every write verb accepts ``--plan``: it prints the commands it would run, as
JSON when asked, and writes nothing. That flag is what lets ``clixz-mcpd``
expose mutations to an automated caller without holding any privilege — the
daemon only ever runs the planning half, and a human runs the other.
"""

from __future__ import annotations

import json as jsonlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from . import compose as compose_mod
from . import npm as npm_mod
from .archive import archive_service, list_archived
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
    declared_urls,
    manifest_json,
    scaffold_template,
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
from .scaffold import CreateRequest, create_service, plan_create
from .system import CommandExecutionError, missing_bins

app = typer.Typer(
    name="clixz",
    help="Inventory, check and create the Docker services under /srv/docker.",
    no_args_is_help=True,
    add_completion=True,
)
image_app = typer.Typer(help="Self-built image build contexts under /opt/images.")
app.add_typer(image_app, name="image")

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

@app.command("ls")
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


@app.command("show")
def show_cmd(
    service: Annotated[str, typer.Argument(autocompletion=_complete_service)],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Everything clixz knows about one service."""
    category, name, path = _resolve(service)
    image, ports, containers = compose_mod.summarize(path / COMPOSE)
    report = audit_service(ctx.config, category, name)
    lint = compose_mod.lint_compose(path / COMPOSE, path)

    payload = {
        "category": category, "service": name, "path": str(path),
        "image": image, "ports": ports, "containers": containers,
        "owner": ctx.config.category(category).owner,
        "permissions": [
            {"path": str(f.path), "severity": f.severity.value, "message": f.message}
            for f in report.findings
        ],
        "lint": [
            {"service": f.service, "level": f.level, "message": f.message} for f in lint
        ],
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
            f"  [{style}]{finding.level:5}[/{style}] {escape(prefix + finding.message)}"
        )


def _print_finding(finding: Finding, indent: str = "  ") -> None:
    style = _STYLE[finding.severity]
    console.print(
        f"{indent}[{style}]{_SYMBOL[finding.severity]}[/{style}] "
        f"{escape(str(finding.path))} — {escape(finding.message)}"
    )


@app.command("check")
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

    if service:
        cat, name, _ = _resolve(service)
        reports = [audit_service(ctx.config, cat, name)]
    else:
        reports = audit_all(ctx.config, category)

    lint: dict[str, list] = {}
    for report in reports:
        if report.service:
            lint[report.name] = compose_mod.lint_compose(report.path / COMPOSE, report.path)

    stray = unknown_category_dirs(ctx.config) if not service else []
    errors = sum(1 for r in reports for f in r.findings if f.severity is Severity.ERROR)
    warns = sum(1 for r in reports for f in r.findings if f.severity is Severity.WARN)
    lint_errors = sum(1 for fs in lint.values() for f in fs if f.level == "error")

    if json_out:
        emit({
            "config": {"source": str(ctx.source) if ctx.source else None, "issues": raw_issues},
            "services": [
                {
                    "name": r.name or r.category, "path": str(r.path),
                    "severity": r.worst.value,
                    "findings": [
                        {"path": str(f.path), "severity": f.severity.value,
                         "message": f.message, "fix": f.fix}
                        for f in r.findings if verbose or f.severity is not Severity.OK
                    ],
                    "lint": [
                        {"service": f.service, "level": f.level, "message": f.message}
                        for f in lint.get(r.name, [])
                    ],
                }
                for r in reports
            ],
            "unknown_directories": [str(p) for p in stray],
            "summary": {"errors": errors, "warnings": warns, "lint_errors": lint_errors},
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
        if not shown and not service_lint:
            continue
        label = report.name or f"{report.category}/"
        console.print(f"[bold]{label}[/bold]")
        for finding in shown:
            _print_finding(finding)
        for finding in service_lint:
            style = _LINT_STYLE[finding.level]
            prefix = f"{finding.service}: " if finding.service else ""
            console.print(
                f"  [{style}]{finding.level:5}[/{style}] {COMPOSE} — "
                f"{escape(prefix + finding.message)}"
            )

    for path in stray:
        console.print(f"[yellow]![/yellow] {path} is not a declared category")

    console.print(
        f"\n[dim]{len(reports)} target(s) — "
        f"{errors} error(s), {warns} warning(s), {lint_errors} compose error(s).[/dim]"
    )
    if errors or raw_issues:
        console.print("[dim]Run `clixz fix` to repair the permission findings.[/dim]")
    raise typer.Exit(code=1 if (errors or raw_issues) else 0)


@app.command("exposed")
def exposed_cmd(
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Compare what the reverse proxy publishes against what the tree declares.

    Reading the NPM database needs root. Without it the command reports what it
    could not read rather than pretending everything is fine.
    """
    database = ctx.config.npm.database
    if database is None:
        message = "no npm.database configured — nothing to cross-check"
        if json_out:
            return emit({"available": False, "reason": message})
        console.print(f"[yellow]![/yellow] {message}")
        return

    try:
        hosts = npm_mod.read_proxy_hosts(database)
    except npm_mod.NpmUnavailable as exc:
        if json_out:
            return emit({"available": False, "reason": str(exc)})
        err.print(f"[yellow]![/yellow] {exc}")
        raise typer.Exit(code=0)

    report = npm_mod.cross_check(
        hosts, declared_urls(ctx.config), npm_mod.running_containers(),
    )

    if json_out:
        return emit({
            "available": True,
            "hosts": [
                {"domains": h.domains, "enabled": h.enabled,
                 "access_list_id": h.access_list_id, "target": h.target}
                for h in report.hosts
            ],
            "findings": [{"level": lvl, "message": msg} for lvl, msg in report.findings],
            "summary": {"total": len(report.hosts), "enabled": len(report.enabled_hosts)},
        })

    table = Table(box=None, pad_edge=False)
    for column in ("DOMAIN", "TARGET", "ENABLED", "ACCESS LIST"):
        table.add_column(column, overflow="fold")
    for host in report.hosts:
        table.add_row(
            ", ".join(host.domains), host.target,
            "[green]yes[/green]" if host.enabled else "[dim]no[/dim]",
            "[dim]none[/dim]" if host.access_list_id == 0 else str(host.access_list_id),
        )
    console.print(table)

    if report.findings:
        console.print()
        for level, message in report.findings:
            style = _LINT_STYLE[level]
            console.print(f"[{style}]{level:5}[/{style}] {escape(message)}")
    console.print(
        f"\n[dim]{len(report.hosts)} proxy host(s), "
        f"{len(report.enabled_hosts)} enabled.[/dim]"
    )


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


@app.command("new")
def new_cmd(
    service: Annotated[str, typer.Argument(help="category/service")],
    plan: Annotated[bool, typer.Option("--plan", help="Print the plan, write nothing.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Create a service tree with a compose template you are meant to edit."""
    if "/" not in service:
        err.print("[red]ERROR[/red] Give a category/service, e.g. apps/myapp.")
        raise typer.Exit(code=2)
    category, _, name = service.partition("/")

    try:
        commands = plan_create(ctx.config, CreateRequest(category, name))
    except (KeyError, ValueError, RuntimeError) as exc:
        if json_out:
            emit({"ok": False, "error": str(exc)})
            raise typer.Exit(code=2)
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2)

    if plan:
        return _render_plan(commands, json_out=json_out, action="new", target=service)

    ensure_root()
    if not yes and not json_out:
        _render_plan(commands, json_out=False, action="new", target=service)
        if not typer.confirm("Create it?"):
            raise typer.Exit(code=1)

    try:
        executed = create_service(ctx.config, CreateRequest(category, name))
    except (CommandExecutionError, RuntimeError, OSError) as exc:
        err.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1)

    if json_out:
        return emit({"ok": True, "created": service, "commands": executed})
    console.print(f"[green]✓[/green] Created {service}.")
    console.print(f"  Edit {ctx.config.root_dir / category / name / COMPOSE}, "
                  f"then `clixz check {service}`.")


@app.command("fix")
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


@app.command("rm")
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

@app.command("meta")
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


@app.command("manifest")
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
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(manifest_json(result.manifest), encoding="utf-8")
    subprocess.run(["chmod", "644", str(destination)], check=False)

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


@app.command("config")
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
        "npm_database": str(config.npm.database) if config.npm.database else None,
        "issues": issues,
    }
    if json_out:
        return emit(payload)

    console.print(f"[bold]Source[/bold]     {payload['source']}")
    console.print(f"[bold]Root[/bold]       {payload['root_dir']}")
    console.print(f"[bold]Manifest[/bold]   {payload['manifest']}")
    console.print(f"[bold]Images[/bold]     {payload['images_dir']}")
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


def cli_main() -> None:  # pragma: no cover
    app()
