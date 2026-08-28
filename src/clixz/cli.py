"""clixz CLI entry point."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__, compat
from .config import Config, RuleConfig, load_config, load_raw_config, validate_config
from .policy import (
    DevOverlay,
    Finding,
    ServiceReport,
    Severity,
    apply_findings,
    audit_category,
    audit_external_dir,
    audit_service,
    list_categories,
    list_external_subdirs,
    list_services,
    plan_path,
    resolve_service,
)
from .archive import archive_service, list_archived
from .scaffold import CreateRequest, create_service, validate_service_name
from .spec import (
    SPEC_FILENAME,
    SpecError,
    render_compose,
    spec_from_dict,
    spec_json,
)
from .spec import validate as validate_spec
from .update import (
    UPDATABLE,
    UpdateRequest,
    update_from_patch,
    update_service,
    validate_target,
)
from .image import DOCKERFILE_NAME, dockerfile_template, validate_image_name
from .meta import (
    SERVICE_FILENAME,
    ManifestResult,
    build_manifest,
    manifest_json,
    scaffold_template,
)
from .dev import (
    acl_disable_cmds,
    acl_enable_cmds,
    add_service,
    mount_targets,
    read_enabled,
    remove_service,
    resolve_principal,
)
from .system import (
    CommandExecutionError,
    CommandRunner,
    check_required_bins,
    detect_acl_support,
    group_exists,
    principal_exists,
    read_acl,
    user_exists,
)

app = typer.Typer(
    name="clixz",
    help="CLI to manage Docker services under /srv/docker.",
    no_args_is_help=True,
    add_completion=True,
)
console = Console()
err_console = Console(stderr=True)


# ─── Global state ─────────────────────────────────────────────────────────────

class Ctx:
    config: Config
    config_source: Optional[Path]
    acl_enabled: bool
    principals_available: dict[str, bool]


ctx = Ctx()


# ─── Privilege elevation ──────────────────────────────────────────────────────

def ensure_root() -> None:
    """Re-exec the current invocation under ``sudo`` when not already root.

    Mutating commands chown/chmod/setfacl under the root dir and write into
    system locations (``/srv/docker``, ``/etc/clixz``), all of which need root.
    Rather than make the user remember to prefix every call with ``sudo``, we
    transparently re-exec the exact same command through sudo. A no-op when
    already running as root, or when ``CLIXZ_NO_SUDO`` is set (for containers,
    CI, or users who'd rather manage elevation themselves).
    """
    if os.geteuid() == 0 or compat.env("NO_SUDO"):
        return
    if shutil.which("sudo") is None:
        err_console.print(
            "[red]ERROR[/red] This command needs root privileges and 'sudo' "
            "was not found. Re-run as root."
        )
        raise typer.Exit(code=2)
    # Resolve argv[0] to an absolute path so sudo's reduced PATH still finds it,
    # then re-exec through the *same* interpreter. --preserve-env=EDITOR keeps
    # `clixz edit` opening the user's editor across the privilege boundary.
    script = sys.argv[0]
    if not os.path.isabs(script):
        script = shutil.which(script) or os.path.abspath(script)
    console.print("[dim]Elevating privileges with sudo…[/dim]")
    try:
        os.execvp(
            "sudo",
            ["sudo", "--preserve-env=EDITOR", sys.executable, script, *sys.argv[1:]],
        )
    except OSError as e:  # pragma: no cover - exec failure is environment-specific
        err_console.print(f"[red]ERROR[/red] Failed to elevate via sudo: {e}")
        raise typer.Exit(code=2)


# ─── Shell completion ─────────────────────────────────────────────────────────

def _complete_service(incomplete: str) -> list[tuple[str, str]]:
    """Complete service arguments: bare names and ``category/service`` forms.

    Runs in a separate completion invocation (the command callbacks are not
    executed), so it loads the config independently. Any failure yields no
    suggestions rather than breaking the user's shell.
    """
    try:
        cfg, _ = load_config(None)
    except Exception:  # noqa: BLE001 - completion must never raise
        return []
    items: list[tuple[str, str]] = []
    for cat, svc, _ in list_services(cfg):
        full = f"{cat}/{svc}"
        if svc.startswith(incomplete):
            items.append((svc, full))
        if full.startswith(incomplete):
            items.append((full, "service"))
    return items


def _complete_category(incomplete: str) -> list[str]:
    """Complete category options from the configured categories."""
    try:
        cfg, _ = load_config(None)
    except Exception:  # noqa: BLE001 - completion must never raise
        return []
    return [c for c in sorted(cfg.categories) if c.startswith(incomplete)]


def _complete_image(incomplete: str) -> list[str]:
    """Complete image names from existing build contexts under the images dir."""
    try:
        cfg, _ = load_config(None)
    except Exception:  # noqa: BLE001 - completion must never raise
        return []
    return [
        p.name for p in list_external_subdirs(cfg.images)
        if p.name.startswith(incomplete)
    ]


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"clixz {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    config_path: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Path to config.yaml (overrides defaults)."),
    ] = None,
    version: Annotated[
        Optional[bool],
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """Manage Docker services under /srv/docker (clixz rules)."""
    missing = check_required_bins()
    if missing:
        err_console.print(f"[red]ERROR[/red] Missing required binaries: {', '.join(missing)}")
        raise typer.Exit(code=2)
    try:
        cfg, source = load_config(config_path)
    except (FileNotFoundError, ValueError) as e:
        err_console.print(f"[red]ERROR[/red] Config: {e}")
        raise typer.Exit(code=2)
    ctx.config = cfg
    ctx.config_source = source
    ctx.acl_enabled = detect_acl_support(cfg.root_dir)
    ctx.principals_available = {
        name: principal_exists(principal.name, principal.kind)
        for name, principal in cfg.settings.principals.items()
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _severity_style(sev: Severity) -> str:
    return {
        Severity.OK: "green",
        Severity.DRIFT: "yellow",
        Severity.WARN: "magenta",
        Severity.ERROR: "red",
    }[sev]


def _severity_symbol(sev: Severity) -> str:
    return {
        Severity.OK: "✓",
        Severity.DRIFT: "✗",
        Severity.WARN: "!",
        Severity.ERROR: "✗",
    }[sev]


def _print_runtime_banner() -> None:
    src = str(ctx.config_source) if ctx.config_source else "<bundled default>"
    principals = ", ".join(
        f"{p.name}({p.kind})" for p in ctx.config.settings.principals.values()
    )
    console.print(
        f"[dim]root={ctx.config.root_dir}  "
        f"principals={principals}  "
        f"acl={'on' if ctx.acl_enabled else 'off'}  "
        f"config={src}[/dim]"
    )


def _check_config_structure() -> list[str]:
    """Validate the raw config structure and print a Config section. Returns issues."""
    try:
        raw = load_raw_config(ctx.config_source)
        issues = validate_config(raw)
    except (OSError, ValueError) as e:
        issues = [f"could not read config: {e}"]
    console.print("\n[bold]Config[/bold]")
    if not issues:
        console.print("  [green]✓ structure OK[/green]")
    else:
        for issue in issues:
            console.print(f"  [red]✗[/red] {issue}")
    return issues


def _dev_enabled_set() -> set[tuple[str, str]]:
    """Services currently mounted into code-server (the dev compose managed block)."""
    dev = ctx.config.dev
    if not dev.compose.is_file():
        return set()
    try:
        text = dev.compose.read_text(encoding="utf-8")
    except OSError:
        return set()
    return set(read_enabled(text, ctx.config.root_dir, dev.mount_base))


def _dev_overlay(category: str, service: str, enabled: set[tuple[str, str]]) -> Optional[DevOverlay]:
    """The dev ACL overlay expected on a dev-enabled service, or None.

    Resolves the dev principal softly: a misconfigured ``dev.principal`` simply
    means no overlay (the config check reports it separately) rather than a crash.
    """
    if (category, service) not in enabled:
        return None
    p = resolve_principal(ctx.config.settings.principals, ctx.config.dev.principal)
    if p is None:
        return None
    return DevOverlay(kind=p.kind, name=p.name, perms=ctx.config.dev.perms)


def _print_finding(finding: Finding, *, indent: str = "  ") -> None:
    style = _severity_style(finding.severity)
    sym = _severity_symbol(finding.severity)
    console.print(
        f"{indent}[{style}]{sym}[/{style}] "
        f"[dim]{finding.rule_name:14}[/dim] {finding.path}"
    )
    for issue in finding.issues:
        console.print(f"{indent}    [dim]→[/dim] {issue}")


def _display_target_for_apply(path: Path) -> str:
    try:
        rel = path.resolve().relative_to(ctx.config.root_dir.resolve())
    except ValueError:
        return str(path)
    parts = rel.parts
    if len(parts) >= 2 and parts[0] in ctx.config.categories:
        return f"{parts[0]}/{parts[1]}"
    if len(parts) >= 1 and parts[0] in ctx.config.categories:
        return parts[0]
    return str(path)


def _print_finding_apply(finding: Finding, *, indent: str = "  ") -> None:
    style = _severity_style(finding.severity)
    sym = _severity_symbol(finding.severity)
    target = _display_target_for_apply(finding.path)
    console.print(
        f"{indent}[{style}]{sym}[/{style}] "
        f"[dim]{finding.rule_name:14}[/dim] {target}"
    )
    for issue in finding.issues:
        console.print(f"{indent}    [dim]→[/dim] {issue}")


# ─── Compose parsing for `list` ───────────────────────────────────────────────

_IMAGE_RE = re.compile(r"^\s*image:\s*(.+?)\s*$", re.MULTILINE)
_EXPOSE_RE = re.compile(r"^\s*-\s*[\"']?(\d+(?:/\w+)?)[\"']?\s*$", re.MULTILINE)


def _parse_compose_summary(compose_path: Path) -> tuple[str, list[str]]:
    """Cheap parse of image + expose ports without pulling in a YAML lib for this view."""
    if not compose_path.is_file():
        return "—", []
    try:
        text = compose_path.read_text(encoding="utf-8")
    except OSError:
        return "?", []
    image_match = _IMAGE_RE.search(text)
    image = image_match.group(1).strip().strip("\"'") if image_match else "—"
    # Capture ports under expose: only
    ports: list[str] = []
    in_expose = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("expose:"):
            in_expose = True
            continue
        if in_expose:
            if stripped.startswith("- "):
                p = stripped[2:].strip().strip("\"'")
                ports.append(p)
            elif stripped and not line.startswith((" ", "\t")):
                in_expose = False
            elif stripped and ":" in stripped and not stripped.startswith("- "):
                in_expose = False
    return image, ports


# ─── Commands ─────────────────────────────────────────────────────────────────

@app.command("list")
def list_cmd(
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category", "-C", help="Filter by category.",
            autocompletion=_complete_category,
        ),
    ] = None,
) -> None:
    """List services with image, ports, and compliance status."""
    _print_runtime_banner()

    services = list_services(ctx.config, category=category)
    if not services:
        console.print("[dim]No services found.[/dim]")
        raise typer.Exit()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Category")
    table.add_column("Service")
    table.add_column("Image")
    table.add_column("Ports")
    table.add_column("Status")

    n_compliant = 0
    n_drift = 0
    n_warn = 0

    dev_enabled = _dev_enabled_set()
    for cat, svc, path in services:
        image, ports = _parse_compose_summary(path / "compose.yaml")
        report = audit_service(
            ctx.config, cat, svc,
            acl_enabled=ctx.acl_enabled,
            principals_available=ctx.principals_available,
            dev=_dev_overlay(cat, svc, dev_enabled),
        )
        if report.compliant:
            status = Text("✓ ok", style="green")
            n_compliant += 1
        elif report.drift_count > 0:
            status = Text(f"✗ {report.drift_count} drift", style="yellow")
            n_drift += 1
            if report.warn_count:
                status.append(f", {report.warn_count} warn", style="magenta")
        else:
            status = Text(f"! {report.warn_count} warn", style="magenta")
            n_warn += 1

        table.add_row(
            cat, svc, image,
            ", ".join(ports) if ports else "—",
            status,
        )

    console.print(table)
    console.print(
        f"[dim]Total {len(services)} — "
        f"[green]{n_compliant} compliant[/green], "
        f"[yellow]{n_drift} with drift[/yellow], "
        f"[magenta]{n_warn} warn-only[/magenta][/dim]"
    )


@app.command("check")
def check_cmd(
    service: Annotated[
        Optional[str],
        typer.Argument(
            help="Service name (e.g. 'bitwarden' or 'apps/bitwarden'). Default: all.",
            autocompletion=_complete_service,
        ),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show OK findings too.")] = False,
) -> None:
    """Audit config structure + permissions/ACL (read-only). Non-zero on drift."""
    _print_runtime_banner()

    config_issues = _check_config_structure()
    dev_enabled = _dev_enabled_set()

    if service:
        try:
            cat, svc, _ = resolve_service(ctx.config, service)
            reports = [audit_service(
                ctx.config, cat, svc,
                acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
                dev=_dev_overlay(cat, svc, dev_enabled),
            )]
        except ValueError as e:
            err_console.print(f"[red]ERROR[/red] {e}")
            raise typer.Exit(code=2)
    else:
        reports = [
            audit_service(
                ctx.config, cat, svc,
                acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
                dev=_dev_overlay(cat, svc, dev_enabled),
            )
            for cat, svc, _ in list_services(ctx.config)
        ]

    # Also audit each category directory once
    cat_findings: dict[str, Finding] = {}
    for cat in list_categories(ctx.config):
        cat_findings[cat] = audit_category(
            ctx.config, cat,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
        )

    total_drift = 0
    total_warn = 0
    for f in cat_findings.values():
        if f.severity is Severity.DRIFT:
            total_drift += 1
        elif f.severity is Severity.WARN:
            total_warn += 1

    # Print category findings (only non-OK or in verbose)
    if any(f.severity is not Severity.OK for f in cat_findings.values()) or verbose:
        console.print("\n[bold]Categories[/bold]")
        for f in cat_findings.values():
            if verbose or f.severity is not Severity.OK:
                _print_finding(f)

    for report in reports:
        if report.compliant and not verbose:
            console.print(
                f"\n[bold]{report.category}/{report.service}[/bold] [green]✓ compliant[/green]"
            )
            continue
        marker = "[green]✓[/green]" if report.compliant else "[yellow]✗[/yellow]"
        console.print(f"\n[bold]{report.category}/{report.service}[/bold] {marker}")
        for finding in report.findings:
            if verbose or finding.severity is not Severity.OK:
                _print_finding(finding)
        total_drift += report.drift_count
        total_warn += report.warn_count

    # Service descriptors (service.yaml) — structural/content validation.
    manifest_result = build_manifest(ctx.config)
    if manifest_result.errors or (verbose and manifest_result.warnings):
        console.print("\n[bold]Service descriptors[/bold]")
        for e in manifest_result.errors:
            console.print(f"  [red]✗[/red] {e}")
        if verbose:
            for w in manifest_result.warnings:
                console.print(f"  [magenta]![/magenta] {w}")
    else:
        console.print(
            f"\n[bold]Service descriptors[/bold] "
            f"[green]✓ {manifest_result.public_count} public, "
            f"{manifest_result.private_count} private[/green]"
        )

    # External directories (images / repos) — owner/mode of each build context.
    ext_findings: list[Finding] = []
    for label, ext in (("images", ctx.config.images), ("repos", ctx.config.repos)):
        ext_findings.extend(audit_external_dir(
            ctx.config, ext, f"{label}_dir",
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
            file_name=DOCKERFILE_NAME if label == "images" else None,
        ))
    if any(f.severity is not Severity.OK for f in ext_findings) or verbose:
        console.print("\n[bold]External dirs (images / repos)[/bold]")
        for f in ext_findings:
            if verbose or f.severity is not Severity.OK:
                _print_finding(f)
    total_drift += sum(1 for f in ext_findings if f.severity is Severity.DRIFT)
    total_warn += sum(1 for f in ext_findings if f.severity is Severity.WARN)

    console.print(
        f"\n[dim]Summary:[/dim] "
        f"[red]{len(config_issues)} config issue(s)[/red], "
        f"[red]{len(manifest_result.errors)} descriptor error(s)[/red], "
        f"[yellow]{total_drift} drift[/yellow], "
        f"[magenta]{total_warn} warn-only[/magenta]"
    )

    if total_drift > 0 or config_issues or manifest_result.errors:
        raise typer.Exit(code=1)


@app.command("apply")
def apply_cmd(
    service: Annotated[
        Optional[str],
        typer.Argument(
            help="Service name. Default: all.",
            autocompletion=_complete_service,
        ),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt.")] = False,
) -> None:
    """Apply correct permissions/ACL to services after confirmation."""
    ensure_root()
    _print_runtime_banner()

    if service:
        try:
            cat, svc, _ = resolve_service(ctx.config, service)
            targets: list[tuple[str, str]] = [(cat, svc)]
        except ValueError as e:
            err_console.print(f"[red]ERROR[/red] {e}")
            raise typer.Exit(code=2)
    else:
        targets = [(c, s) for c, s, _ in list_services(ctx.config)]

    # Audit categories AND services to build the full finding list
    all_findings: list[Finding] = []
    if not service:
        for cat in list_categories(ctx.config):
            all_findings.append(audit_category(
                ctx.config, cat,
                acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
            ))
    else:
        # When targeting one service, also include its category
        cat = targets[0][0]
        all_findings.append(audit_category(
            ctx.config, cat,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
        ))

    dev_enabled = _dev_enabled_set()
    for cat, svc in targets:
        report = audit_service(
            ctx.config, cat, svc,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
            dev=_dev_overlay(cat, svc, dev_enabled),
        )
        all_findings.extend(report.findings)

    # External dirs (images / repos) when applying to everything.
    if not service:
        for label, ext in (("images", ctx.config.images), ("repos", ctx.config.repos)):
            all_findings.extend(audit_external_dir(
                ctx.config, ext, f"{label}_dir",
                acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
                file_name=DOCKERFILE_NAME if label == "images" else None,
            ))

    drifts = [f for f in all_findings if f.severity is Severity.DRIFT]
    warns = [f for f in all_findings if f.severity is Severity.WARN]
    errors = [f for f in all_findings if f.severity is Severity.ERROR]

    if not drifts and not warns and not errors:
        console.print("[green]✓ All compliant — nothing to do.[/green]")
        raise typer.Exit()

    if drifts:
        console.print(f"\n[yellow]Planned changes ({len(drifts)}):[/yellow]")
        for f in drifts:
            _print_finding_apply(f)
            for cmd in f.fixes:
                console.print(f"      [dim]$[/dim] {' '.join(cmd)}")

    if warns:
        console.print(f"\n[magenta]Audit-only warnings ({len(warns)}) — NOT touched:[/magenta]")
        for f in warns:
            _print_finding_apply(f)

    if errors:
        console.print(f"\n[red]Errors ({len(errors)}) — blocking:[/red]")
        for f in errors:
            _print_finding_apply(f)
        raise typer.Exit(code=2)

    if not yes and not typer.confirm(f"\nApply {len(drifts)} fix(es)?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    try:
        result = apply_findings(drifts, dry_run=False)
    except CommandExecutionError as e:
        err_console.print("[red]ERROR[/red] Failed to apply fixes: a shell command failed.")
        err_console.print(f"[red]Command[/red]: {' '.join(e.command)}")
        if e.stdout.strip():
            err_console.print(f"[red]stdout[/red]:\n{e.stdout.rstrip()}")
        if e.stderr.strip():
            err_console.print(f"[red]stderr[/red]:\n{e.stderr.rstrip()}")
        raise typer.Exit(code=2)
    console.print(f"\n[green]✓ Done — {len(result.commands_run)} command(s) executed.[/green]")


@app.command("create")
def create_cmd(
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category", "-C", help="Service category.",
            autocompletion=_complete_category,
        ),
    ] = None,
    name: Annotated[
        Optional[str],
        typer.Option("--name", "-n", help="Service name."),
    ] = None,
    spec_file: Annotated[
        Optional[Path],
        typer.Option(
            "--spec", "-s",
            help="JSON spec; generates compose.yaml instead of leaving it empty "
                 "('-' reads stdin). Takes category and name from the spec.",
        ),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """Scaffold a new service: directories, then a compose.yaml from a spec (or empty)."""
    ensure_root()
    _print_runtime_banner()

    cfg = ctx.config

    spec = None
    if spec_file is not None:
        import json

        try:
            spec = validate_spec(spec_from_dict(json.loads(_read_new_content(spec_file))), cfg)
        except (SpecError, ValueError) as e:
            err_console.print(f"[red]ERROR[/red] {e}")
            raise typer.Exit(code=2)
        # The spec carries its own identity; a divergent --category/--name would
        # produce a tree that does not match the compose written into it.
        if (category and category != spec.category) or (name and name != spec.service):
            err_console.print(
                "[red]ERROR[/red] --category/--name conflict with the spec "
                f"({spec.category}/{spec.service})."
            )
            raise typer.Exit(code=2)
        category, name = spec.category, spec.service

    # Interactive prompts for missing arguments
    if not category:
        cats = sorted(cfg.categories)
        console.print("Available categories: " + ", ".join(cats))
        category = typer.prompt("Category", default=cats[0])
    if category not in cfg.categories:
        err_console.print(
            f"[red]ERROR[/red] Unknown category '{category}'. "
            f"Authorized: {', '.join(sorted(cfg.categories))}"
        )
        raise typer.Exit(code=2)

    if not name:
        name = typer.prompt("Service name")
    try:
        validate_service_name(name)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    req = CreateRequest(category=category, service=name)
    svc_path = cfg.root_dir / category / name

    console.print()
    console.print("[bold]Will create:[/bold]")
    console.print(f"  path  : {svc_path}/")
    console.print(f"  owner : {cfg.category(category).owner_spec}")
    console.print("  files : compose.yaml, .env (empty), service.yaml (template), config/, data/")
    console.print()

    if not yes and not typer.confirm("Create this service?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    try:
        executed = create_service(
            cfg, req,
            dry_run=False,
            acl_enabled=ctx.acl_enabled,
            principals_available=ctx.principals_available,
        )
    except (ValueError, RuntimeError) as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    for cmd in executed:
        console.print(f"  [green]RUN[/green] {' '.join(cmd)}")

    if spec is not None:
        try:
            _write_spec_and_compose(cfg, spec)
        except (CommandExecutionError, OSError) as e:
            err_console.print(f"[red]ERROR[/red] Could not write the generated files: {e}")
            raise typer.Exit(code=2)
        console.print(
            f"  [green]✓[/green] compose.yaml generated from the spec "
            f"({SPEC_FILENAME} kept alongside)"
        )

    console.print(f"\n[green]✓ Created {svc_path}[/green]")
    console.print(
        f"  Next: edit {svc_path}/compose.yaml, .env and {SERVICE_FILENAME} "
        "(set public: true to show it on the dashboard), then deploy."
    )

    # Refresh the dashboard manifest so a public descriptor shows up right away.
    # Best-effort: a manifest write failure must not fail the create itself.
    try:
        result = build_manifest(cfg)
        _write_manifest(result, dry_run=False)
        console.print(
            f"  [dim]Manifest refreshed: {result.public_count} public service(s).[/dim]"
        )
    except (CommandExecutionError, OSError) as e:
        console.print(f"  [magenta]![/magenta] Could not refresh manifest: {e}")
        console.print("    Run [bold]clixz manifest[/bold] once permissions allow.")


# ─── update: rewrite compose.yaml / service.yaml of an existing service ───────

def _read_new_content(from_file: Optional[Path]) -> str:
    """Read replacement content from a file, or from stdin when given ``-``."""
    if from_file is None:
        err_console.print(
            "[red]ERROR[/red] --from-file is required (use '-' to read stdin)."
        )
        raise typer.Exit(code=2)
    if str(from_file) == "-":
        return sys.stdin.read()
    try:
        return from_file.read_text(encoding="utf-8")
    except OSError as e:
        err_console.print(f"[red]ERROR[/red] Could not read {from_file}: {e}")
        raise typer.Exit(code=2)


def _print_diff(previous: str, content: str, path: Path) -> None:
    import difflib

    diff = list(difflib.unified_diff(
        previous.splitlines(), content.splitlines(),
        fromfile=f"a/{path.name}", tofile=f"b/{path.name}", lineterm="",
    ))
    if not diff:
        console.print("  [dim](no textual change)[/dim]")
        return
    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            console.print(f"  [green]{line}[/green]")
        elif line.startswith("-") and not line.startswith("---"):
            console.print(f"  [red]{line}[/red]")
        elif line.startswith("@@"):
            console.print(f"  [cyan]{line}[/cyan]")
        else:
            console.print(f"  [dim]{line}[/dim]")


def _write_spec_and_compose(cfg: Config, spec) -> None:
    """Write the generated compose.yaml and its spec.json, with correct perms."""
    svc_path = cfg.root_dir / spec.category / spec.service
    runner = CommandRunner(dry_run=False)
    for path, content, rule_name in (
        (svc_path / "compose.yaml", render_compose(spec, cfg), "compose_file"),
        (svc_path / SPEC_FILENAME, spec_json(spec), "spec_file"),
    ):
        runner.write_file(path, content)
        rule = cfg.rule_or_default(rule_name)
        owner = rule.owner or cfg.category(spec.category).owner_spec
        for cmd in plan_path(
            path, rule, owner, cfg, is_dir=False,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
        ):
            runner.run(cmd)


def _update_from_patch(service: str, patch_file: Path, *, yes: bool, dry_run: bool) -> None:
    """`update --patch`: merge a JSON patch into the spec and regenerate compose.yaml."""
    import json

    raw = _read_new_content(patch_file)
    try:
        patch = json.loads(raw)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] Invalid JSON patch: {e}")
        raise typer.Exit(code=2)

    if not dry_run:
        ensure_root()
    _print_runtime_banner()

    try:
        cat, svc, _ = resolve_service(ctx.config, service)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    def run(*, write: bool):
        return update_from_patch(
            ctx.config, cat, svc, patch,
            dry_run=not write, acl_enabled=ctx.acl_enabled,
            principals_available=ctx.principals_available,
        )

    try:
        compose_r, spec_r = run(write=False)
    except (SpecError, ValueError, RuntimeError) as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    console.print(f"\n[bold]Patch {cat}/{svc}[/bold]  {', '.join(sorted(patch))}")
    if spec_r.unchanged and compose_r.unchanged:
        console.print("  [green]✓ already up to date — nothing to do.[/green]")
        raise typer.Exit()
    console.print(f"\n[dim]{spec_r.path.name}[/dim]")
    _print_diff(spec_r.previous, spec_r.content, spec_r.path)
    console.print(f"\n[dim]{compose_r.path.name}[/dim] [dim](regenerated)[/dim]")
    _print_diff(compose_r.previous, compose_r.content, compose_r.path)

    if dry_run:
        console.print("\n[dim]Dry-run — nothing written.[/dim]")
        raise typer.Exit()
    if not yes and not typer.confirm("\nApply this patch?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    try:
        compose_r, spec_r = run(write=True)
    except (CommandExecutionError, SpecError, ValueError, RuntimeError, OSError) as e:
        err_console.print(f"[red]ERROR[/red] Could not apply the patch: {e}")
        raise typer.Exit(code=2)

    console.print(f"\n[green]✓ Patched {cat}/{svc}[/green]")
    if compose_r.snapshot:
        console.print(f"  [dim]Previous compose kept at {compose_r.snapshot}[/dim]")
    console.print("  [dim]Redeploy the stack for the new compose to take effect.[/dim]")


@app.command("update")
def update_cmd(
    service: Annotated[
        str,
        typer.Argument(
            help="Service ('category/service' or unique name).",
            autocompletion=_complete_service,
        ),
    ],
    target: Annotated[
        Optional[str],
        typer.Option("--target", "-t", help=f"What to rewrite: {', '.join(sorted(UPDATABLE))}."),
    ] = None,
    from_file: Annotated[
        Optional[Path],
        typer.Option("--from-file", "-f", help="New content ('-' reads stdin)."),
    ] = None,
    patch_file: Annotated[
        Optional[Path],
        typer.Option(
            "--patch", "-p",
            help="JSON patch on the service spec; regenerates compose.yaml ('-' reads stdin).",
        ),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the diff and exit.")] = False,
) -> None:
    """Patch a service spec (--patch), or rewrite compose.yaml / service.yaml (--target)."""
    if patch_file is not None and target is not None:
        err_console.print("[red]ERROR[/red] --patch and --target are mutually exclusive.")
        raise typer.Exit(code=2)
    if patch_file is not None:
        _update_from_patch(service, patch_file, yes=yes, dry_run=dry_run)
        return
    if target is None:
        err_console.print("[red]ERROR[/red] Give --patch (spec) or --target (raw file).")
        raise typer.Exit(code=2)

    try:
        validate_target(target)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    content = _read_new_content(from_file)
    if not dry_run:
        ensure_root()
    _print_runtime_banner()

    try:
        cat, svc, _ = resolve_service(ctx.config, service)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    req = UpdateRequest(category=cat, service=svc, target=target, content=content)
    try:
        result = update_service(
            ctx.config, req,
            dry_run=True,
            acl_enabled=ctx.acl_enabled,
            principals_available=ctx.principals_available,
        )
    except (ValueError, RuntimeError) as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    console.print(f"\n[bold]Update {cat}/{svc}[/bold] → {result.path}")
    for w in result.warnings:
        console.print(f"  [magenta]![/magenta] {w}")
    if result.unchanged:
        console.print("  [green]✓ already up to date — nothing to do.[/green]")
        raise typer.Exit()
    _print_diff(result.previous, result.content, result.path)

    if dry_run:
        console.print("\n[dim]Dry-run — nothing written.[/dim]")
        raise typer.Exit()
    if not yes and not typer.confirm("\nWrite this content?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    try:
        result = update_service(
            ctx.config, req,
            dry_run=False,
            acl_enabled=ctx.acl_enabled,
            principals_available=ctx.principals_available,
        )
    except (CommandExecutionError, ValueError, RuntimeError, OSError) as e:
        err_console.print(f"[red]ERROR[/red] Could not update {result.path}: {e}")
        raise typer.Exit(code=2)

    console.print(f"\n[green]✓ Updated {result.path}[/green]")
    if result.snapshot:
        console.print(f"  [dim]Previous version kept at {result.snapshot}[/dim]")
    if target == "service":
        console.print("  [dim]Run `clixz manifest` to refresh the dashboard.[/dim]")


# ─── archive: retire a service without ever destroying it ─────────────────────

@app.command("archive")
def archive_cmd(
    service: Annotated[
        str,
        typer.Argument(
            help="Service ('category/service' or unique name).",
            autocompletion=_complete_service,
        ),
    ],
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="DESTRUCTIVE: delete instead of archiving. Interactive use only.",
        ),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan and exit.")] = False,
) -> None:
    """Move a service into the archive (default), or delete it with --force."""
    if not dry_run:
        ensure_root()
    _print_runtime_banner()

    try:
        cat, svc, svc_path = resolve_service(ctx.config, service)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    if force:
        console.print(f"\n[red bold]DELETE {cat}/{svc}[/red bold]")
        console.print(f"  [red]Removes {svc_path} and ALL its contents: compose.yaml, "
                      ".env, config/ and data/.[/red]")
        console.print("  [red]This is irreversible — there will be no archive copy.[/red]")
    else:
        console.print(f"\n[bold]Archive {cat}/{svc}[/bold]")
        console.print(f"  moves {svc_path} under {ctx.config.root_dir}/.archive/{cat}/{svc}/")
        console.print("  [dim]Nothing is destroyed; the tree can be moved back.[/dim]")

    if dry_run:
        console.print("\n[dim]Dry-run — nothing changed.[/dim]")
        raise typer.Exit()

    if not yes:
        prompt = "Delete it permanently?" if force else "Archive it?"
        if not typer.confirm(f"\n{prompt}"):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(code=1)
    if force and not yes and not typer.confirm("Really? This cannot be undone"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    try:
        result = archive_service(ctx.config, cat, svc, dry_run=False, force=force)
    except (CommandExecutionError, RuntimeError) as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    if result.forced:
        console.print(f"\n[green]✓ Deleted {result.source}[/green]")
    else:
        console.print(f"\n[green]✓ Archived to {result.destination}[/green]")
    console.print("  [dim]Run `clixz manifest` to refresh the dashboard.[/dim]")


@app.command("archived")
def archived_cmd() -> None:
    """List archived service trees."""
    _print_runtime_banner()
    entries = list_archived(ctx.config)
    if not entries:
        console.print("[dim]Nothing archived.[/dim]")
        raise typer.Exit()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Category")
    table.add_column("Service")
    table.add_column("Archived at (UTC)")
    table.add_column("Path")
    for cat, svc, stamp, path in entries:
        table.add_row(cat, svc, stamp, str(path))
    console.print(table)


# ─── manifest: aggregate service.yaml descriptors for the API/dashboard ───────

def _manifest_owner() -> Optional[str]:
    """The owner ``user:group`` the manifest file should carry, or None.

    Derived from the category the manifest lives under (e.g. ``apps`` →
    ``svc_apps:svc_apps``) so it matches the API service's data directory.
    """
    path = ctx.config.resolved_manifest_path
    try:
        rel = path.resolve().relative_to(ctx.config.root_dir.resolve())
    except ValueError:
        return None
    cat = rel.parts[0] if rel.parts else None
    if cat in ctx.config.categories:
        return ctx.config.category(cat).owner_spec
    return None


def _write_manifest(result: ManifestResult, *, dry_run: bool) -> None:
    """Write the manifest JSON, then fix its owner/mode (644 so the API can read)."""
    path = ctx.config.resolved_manifest_path
    runner = CommandRunner(dry_run=dry_run)
    if not path.parent.exists():
        runner.run(["mkdir", "-p", str(path.parent)])
    runner.write_file(path, manifest_json(result.manifest))
    owner = _manifest_owner()
    if owner:
        user, _, group = owner.partition(":")
        if user_exists(user) and group_exists(group):
            runner.run(["chown", owner, str(path)])
    runner.run(["chmod", "644", str(path)])


def _report_manifest_issues(result: ManifestResult) -> None:
    if result.warnings:
        console.print(f"\n[magenta]Warnings ({len(result.warnings)}):[/magenta]")
        for w in result.warnings:
            console.print(f"  [magenta]![/magenta] {w}")
    if result.errors:
        console.print(
            f"\n[red]Errors ({len(result.errors)}) — invalid descriptors are skipped:[/red]"
        )
        for e in result.errors:
            console.print(f"  [red]✗[/red] {e}")


@app.command("manifest")
def manifest_cmd(
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Validate + preview without writing.")
    ] = False,
) -> None:
    """Aggregate every service.yaml into the API manifest (public services only)."""
    if not dry_run:
        ensure_root()
    _print_runtime_banner()
    result = build_manifest(ctx.config)
    path = ctx.config.resolved_manifest_path

    _report_manifest_issues(result)
    console.print(
        f"\n[bold]Manifest[/bold] → {path}\n"
        f"  [green]{result.public_count} public[/green], "
        f"[dim]{result.private_count} private (excluded from API)[/dim]"
    )

    try:
        _write_manifest(result, dry_run=dry_run)
    except CommandExecutionError as e:
        err_console.print("[red]ERROR[/red] Failed to set manifest permissions (run with sudo?).")
        err_console.print(f"[red]Command[/red]: {' '.join(e.command)}")
        if e.stderr.strip():
            err_console.print(f"[red]stderr[/red]:\n{e.stderr.rstrip()}")
        raise typer.Exit(code=2)
    except OSError as e:
        err_console.print(f"[red]ERROR[/red] Could not write {path}: {e} (run with sudo?)")
        raise typer.Exit(code=2)

    if dry_run:
        console.print("\n[dim]Dry-run — nothing written.[/dim]")
    else:
        console.print(f"\n[green]✓ Wrote manifest ({result.public_count} service(s)).[/green]")
    if result.errors:
        raise typer.Exit(code=1)


# ─── meta: manage service.yaml descriptors ────────────────────────────────────

meta_app = typer.Typer(
    name="meta",
    help="Manage service.yaml dashboard descriptors.",
    no_args_is_help=True,
)
app.add_typer(meta_app, name="meta")


@meta_app.command("scaffold")
def meta_scaffold_cmd(
    service: Annotated[
        str,
        typer.Argument(
            help="Service ('category/service' or unique name).",
            autocompletion=_complete_service,
        ),
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Create a service.yaml template in an existing service (won't overwrite)."""
    ensure_root()
    _print_runtime_banner()
    try:
        cat, svc, svc_path = resolve_service(ctx.config, service)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    descriptor = svc_path / SERVICE_FILENAME
    if descriptor.exists():
        err_console.print(f"[red]ERROR[/red] {descriptor} already exists.")
        raise typer.Exit(code=2)

    console.print(f"\n[bold]Create {cat}/{svc}/{SERVICE_FILENAME}[/bold] (template, public: false)")
    if not yes and not typer.confirm("Create it?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    rule = ctx.config.rule_or_default("service_file")
    owner = rule.owner or ctx.config.category(cat).owner_spec
    runner = CommandRunner(dry_run=False)
    try:
        runner.write_file(descriptor, scaffold_template(cat, svc))
        from .policy import plan_path  # local import: avoids reshuffling module imports
        for cmd in plan_path(
            descriptor, rule, owner, ctx.config, is_dir=False,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
        ):
            runner.run(cmd)
    except (CommandExecutionError, OSError) as e:
        err_console.print(f"[red]ERROR[/red] Could not write {descriptor}: {e} (run with sudo?)")
        raise typer.Exit(code=2)

    console.print(f"[green]✓ Created {descriptor}[/green]")
    console.print(f"  Edit it, then run [bold]clixz manifest[/bold] to publish.")


@meta_app.command("validate")
def meta_validate_cmd(
    service: Annotated[
        Optional[str],
        typer.Argument(
            help="Limit to one service (default: all).",
            autocompletion=_complete_service,
        ),
    ] = None,
) -> None:
    """Validate service.yaml descriptors without writing anything."""
    _print_runtime_banner()
    result = build_manifest(ctx.config)

    def _keep(line: str) -> bool:
        return service is None or line.startswith(f"{service}:") or f"/{service}:" in line

    warnings = [w for w in result.warnings if _keep(w)]
    errors = [e for e in result.errors if _keep(e)]

    if warnings:
        console.print(f"[magenta]Warnings ({len(warnings)}):[/magenta]")
        for w in warnings:
            console.print(f"  [magenta]![/magenta] {w}")
    if errors:
        console.print(f"[red]Errors ({len(errors)}):[/red]")
        for e in errors:
            console.print(f"  [red]✗[/red] {e}")
    if not warnings and not errors:
        console.print("[green]✓ All descriptors valid.[/green]")

    console.print(
        f"\n[dim]{result.public_count} public, {result.private_count} private.[/dim]"
    )
    if errors:
        raise typer.Exit(code=1)


@app.command("show-config")
def show_config_cmd() -> None:
    """Print the resolved configuration."""
    _print_runtime_banner()
    cfg = ctx.config

    console.print(f"\n[bold]Categories[/bold] ({len(cfg.categories)})")
    for name, c in sorted(cfg.categories.items()):
        console.print(f"  {name:12} → {c.owner_spec}")

    console.print("\n[bold]External dirs[/bold]")
    for label, ext in (("images", cfg.images), ("repos", cfg.repos)):
        acl = (
            ", ".join(f"{principal}:{perms}" for principal, perms in ext.acl.items())
            if ext.acl else "—"
        )
        recursive = ", recursive" if ext.recursive else ""
        console.print(
            f"  {label:7} → {ext.dir}  [dim]({ext.owner}, {ext.mode}, acl={acl}{recursive})[/dim]"
        )
        if ext.dockerfile is not None:
            df = ext.dockerfile
            df_acl = (
                ", ".join(f"{principal}:{perms}" for principal, perms in df.acl.items())
                if df.acl else "—"
            )
            df_recursive = ", recursive" if df.recursive else ""
            console.print(
                f"  {'':7}   [dim]dockerfile: {df.owner or ext.owner}, "
                f"{df.mode}, acl={df_acl}{df_recursive}[/dim]"
            )

    console.print(f"\n[bold]Exclude[/bold] ({len(cfg.exclude)})")
    for pattern in cfg.exclude:
        console.print(f"  - {pattern}")

    console.print(f"\n[bold]Rules[/bold] ({len(cfg.rules)})")
    table = Table(show_header=True, header_style="bold dim")
    table.add_column("Rule")
    table.add_column("Mode")
    table.add_column("ACL")
    table.add_column("Audit only")
    table.add_column("Owner override")
    for name, r in cfg.rules.items():
        acl = "—"
        if r.acl:
            acl = ", ".join(f"{principal}:{perms}" for principal, perms in r.acl.items())
        table.add_row(
            name, r.mode,
            acl,
            "yes" if r.audit_only else "no",
            r.owner or "—",
        )
    console.print(table)


@app.command("edit")
def edit_cmd() -> None:
    """Edit the main configuration file."""
    ensure_root()
    cfg_path = Path("/etc/clixz/config.yaml")
    if not cfg_path.exists():
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        src = files("clixz").joinpath("default_config.yaml")
        cfg_path.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"[dim]Created {cfg_path} from bundled defaults.[/dim]")
    editor = os.environ.get("EDITOR")
    if editor and editor.strip():
        parts = shlex.split(editor)
        if not parts:
            err_console.print("[red]ERROR[/red] EDITOR is empty.")
            raise typer.Exit(code=2)
        editor_cmd = parts[0]
        if shutil.which(editor_cmd) is None and not Path(editor_cmd).is_file():
            err_console.print(f"[red]ERROR[/red] Editor not found: {editor_cmd}")
            raise typer.Exit(code=2)
        command = [*parts, str(cfg_path)]
    else:
        command = None
        for candidate in ("nano", "vi", "vim"):
            if shutil.which(candidate):
                command = [candidate, str(cfg_path)]
                break
        if command is None:
            err_console.print("[red]ERROR[/red] No editor found (set $EDITOR).")
            raise typer.Exit(code=2)
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        err_console.print("[red]ERROR[/red] Editor exited with an error.")
        raise typer.Exit(code=2)
    except FileNotFoundError:
        err_console.print(f"[red]ERROR[/red] Editor not found: {command[0]}")
        raise typer.Exit(code=2)


# ─── dev: mount services into code-server ─────────────────────────────────────

dev_app = typer.Typer(
    name="dev",
    help="Make services editable via code-server (boxyz_dev ACL + compose mounts).",
    no_args_is_help=True,
)
app.add_typer(dev_app, name="dev")


def _dev_principal() -> tuple[str, str]:
    """Resolve the configured dev principal by its key *or* its name.

    Accepting either spelling avoids the key-vs-name confusion: with a config
    principal ``dev: {name: boxyz_dev}``, both ``principal: dev`` and
    ``principal: boxyz_dev`` resolve to it.
    """
    principals = ctx.config.settings.principals
    wanted = ctx.config.dev.principal
    p = resolve_principal(principals, wanted)
    if p is None:
        available = ", ".join(f"{k} (name: {pr.name})" for k, pr in principals.items())
        err_console.print(
            f"[red]ERROR[/red] dev.principal '{wanted}' matches no principal by key "
            f"or name. Defined principals: {available or '(none)'}."
        )
        raise typer.Exit(code=2)
    return p.kind, p.name


def _dev_service_dirs(svc_path: Path) -> list[Path]:
    return [p for p in (svc_path / "config", svc_path / "data") if p.is_dir()]


def _run_acl_commands(commands: list[list[str]]) -> None:
    runner = CommandRunner(dry_run=False)
    try:
        for cmd in commands:
            runner.run(cmd)
    except CommandExecutionError as e:
        err_console.print("[red]ERROR[/red] setfacl failed (run with sudo?).")
        err_console.print(f"[red]Command[/red]: {' '.join(e.command)}")
        if e.stderr.strip():
            err_console.print(f"[red]stderr[/red]:\n{e.stderr.rstrip()}")
        raise typer.Exit(code=2)


@dev_app.command("add")
def dev_add_cmd(
    service: Annotated[
        str,
        typer.Argument(
            help="Service ('category/service' or unique name).",
            autocompletion=_complete_service,
        ),
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan and exit.")] = False,
) -> None:
    """Enable a service for editing in code-server."""
    if not dry_run:
        ensure_root()
    _print_runtime_banner()
    cfg, dev = ctx.config, ctx.config.dev

    try:
        cat, svc, svc_path = resolve_service(cfg, service)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    kind, name = _dev_principal()
    if not ctx.acl_enabled:
        err_console.print("[red]ERROR[/red] ACL unsupported on this filesystem.")
        raise typer.Exit(code=2)
    if not principal_exists(name, kind):
        err_console.print(f"[red]ERROR[/red] {kind} '{name}' does not exist on this host.")
        raise typer.Exit(code=2)
    dirs = _dev_service_dirs(svc_path)
    if not dirs:
        err_console.print(f"[red]ERROR[/red] {cat}/{svc} has no config/ or data/ directory.")
        raise typer.Exit(code=2)
    if not dev.compose.is_file():
        err_console.print(f"[red]ERROR[/red] code-server compose not found: {dev.compose}")
        raise typer.Exit(code=2)

    text = dev.compose.read_text(encoding="utf-8")
    new_text = add_service(text, cat, svc, cfg.root_dir, dev.mount_base)
    acl_cmds = acl_enable_cmds(dirs, kind, name, dev.perms)

    console.print(f"\n[bold]Enable {cat}/{svc} for code-server[/bold]")
    console.print(f"  grant [cyan]{name}[/cyan] ({kind}, {dev.perms}, recursive) on:")
    for d in dirs:
        console.print(f"    - {d}")
    console.print(f"  mount into {dev.compose.name}:")
    for t in mount_targets(cat, svc, dev.mount_base):
        console.print(f"    - {t}")
    if new_text == text:
        console.print("  [dim](compose mounts already present)[/dim]")

    if dry_run:
        for cmd in acl_cmds:
            console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
        console.print("\n[dim]Dry-run — nothing changed.[/dim]")
        raise typer.Exit()
    if not yes and not typer.confirm("\nApply?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    _run_acl_commands(acl_cmds)
    if new_text != text:
        dev.compose.write_text(new_text, encoding="utf-8")
    console.print(f"\n[green]✓ {cat}/{svc} is now editable via code-server.[/green]")
    console.print("  [dim]Redeploy code-server for the new mounts to take effect.[/dim]")


@dev_app.command("remove")
def dev_remove_cmd(
    service: Annotated[
        str,
        typer.Argument(
            help="Service ('category/service' or unique name).",
            autocompletion=_complete_service,
        ),
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan and exit.")] = False,
) -> None:
    """Disable a service: revoke its dev ACL and unmount it from code-server."""
    if not dry_run:
        ensure_root()
    _print_runtime_banner()
    cfg, dev = ctx.config, ctx.config.dev

    try:
        cat, svc, svc_path = resolve_service(cfg, service)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    kind, name = _dev_principal()
    if not dev.compose.is_file():
        err_console.print(f"[red]ERROR[/red] code-server compose not found: {dev.compose}")
        raise typer.Exit(code=2)

    text = dev.compose.read_text(encoding="utf-8")
    new_text = remove_service(text, cat, svc, cfg.root_dir, dev.mount_base)
    dirs = _dev_service_dirs(svc_path)
    acl_cmds = acl_disable_cmds(dirs, kind, name) if (ctx.acl_enabled and dirs) else []

    console.print(f"\n[bold]Disable {cat}/{svc}[/bold]")
    console.print(f"  revoke [cyan]{name}[/cyan] ({kind}) ACL (recursive) on:")
    for d in dirs:
        console.print(f"    - {d}")
    console.print(f"  unmount from {dev.compose.name}")
    if new_text == text:
        console.print("  [dim](compose mounts already absent)[/dim]")

    if dry_run:
        for cmd in acl_cmds:
            console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
        console.print("\n[dim]Dry-run — nothing changed.[/dim]")
        raise typer.Exit()
    if not yes and not typer.confirm("\nApply?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    _run_acl_commands(acl_cmds)
    if new_text != text:
        dev.compose.write_text(new_text, encoding="utf-8")
    console.print(f"\n[green]✓ {cat}/{svc} removed from code-server dev.[/green]")


@dev_app.command("list")
def dev_list_cmd() -> None:
    """List services currently editable via code-server."""
    _print_runtime_banner()
    cfg, dev = ctx.config, ctx.config.dev

    if not dev.compose.is_file():
        console.print(f"[dim]No code-server compose at {dev.compose}.[/dim]")
        raise typer.Exit()
    enabled = read_enabled(dev.compose.read_text(encoding="utf-8"), cfg.root_dir, dev.mount_base)
    if not enabled:
        console.print("[dim]No services enabled for dev.[/dim]")
        raise typer.Exit()

    kind, name = _dev_principal()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Category")
    table.add_column("Service")
    table.add_column("Mount")
    table.add_column(f"ACL ({name})")
    for cat, svc in enabled:
        config_dir = cfg.root_dir / cat / svc / "config"
        acl = read_acl(config_dir) if config_dir.is_dir() else None
        if acl is None:
            status = Text("—", style="dim")
        elif (kind, name) in acl.named:
            status = Text("✓", style="green")
        else:
            status = Text("missing", style="yellow")
        table.add_row(cat, svc, f"{dev.mount_base}/{cat}/{svc}", status)
    console.print(table)


# ─── image: manage self-built image build contexts under /opt/images ──────────

image_app = typer.Typer(
    name="image",
    help="Manage self-built image build contexts (/opt/images/<name>).",
    no_args_is_help=True,
)
app.add_typer(image_app, name="image")


def _image_rule() -> RuleConfig:
    """The owner/mode/ACL rule for image build directories (world-readable by default)."""
    img = ctx.config.images
    return RuleConfig(mode=img.mode, acl=img.acl, owner=img.owner)


def _dockerfile_rule() -> RuleConfig:
    """The rule for the Dockerfile inside each image dir.

    Uses the configured ``images.dockerfile`` rule when present (so it can carry
    a custom ACL); otherwise the legacy default (owner = images owner, mode 664,
    no ACL).
    """
    img = ctx.config.images
    return img.dockerfile or RuleConfig(mode="664", acl=None, owner=img.owner)


@image_app.command("add")
def image_add_cmd(
    name: Annotated[str, typer.Argument(help="Image name (directory under the images dir).")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan and exit.")] = False,
) -> None:
    """Scaffold a self-built image build context: dir + owner/mode + Dockerfile."""
    if not dry_run:
        ensure_root()
    _print_runtime_banner()
    img = ctx.config.images

    try:
        validate_image_name(name)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    path = img.dir / name
    if path.exists():
        err_console.print(f"[red]ERROR[/red] {path} already exists.")
        raise typer.Exit(code=2)

    rule = _image_rule()
    dir_cmds = plan_path(
        path, rule, img.owner, ctx.config, is_dir=True,
        acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
    )
    dfile = path / DOCKERFILE_NAME
    df_rule = _dockerfile_rule()
    df_owner = df_rule.owner or img.owner
    df_cmds = plan_path(
        dfile, df_rule, df_owner, ctx.config, is_dir=False,
        acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
    )

    console.print(f"\n[bold]Create image build context[/bold] {path}/")
    console.print(f"  owner : {img.owner}    mode : {img.mode}")
    console.print(f"  files : {DOCKERFILE_NAME} (template, {df_owner}, mode {df_rule.mode})")

    if dry_run:
        for cmd in (*dir_cmds, *df_cmds):
            console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
        console.print("\n[dim]Dry-run — nothing changed.[/dim]")
        raise typer.Exit()
    if not yes and not typer.confirm("\nCreate it?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    runner = CommandRunner(dry_run=False)
    try:
        for cmd in dir_cmds:
            runner.run(cmd)
        runner.write_file(dfile, dockerfile_template(name))
        for cmd in df_cmds:
            runner.run(cmd)
    except (CommandExecutionError, OSError) as e:
        err_console.print(f"[red]ERROR[/red] Could not create {path}: {e} (run with sudo?)")
        raise typer.Exit(code=2)

    console.print(f"\n[green]✓ Created {path}[/green]")
    console.print(f"  Edit {path}/{DOCKERFILE_NAME} + add your sources, then build with Komodo")
    console.print(f"  (context = {path}). The matching /srv/docker service just uses the image.")


@image_app.command("remove")
def image_remove_cmd(
    name: Annotated[
        str,
        typer.Argument(
            help="Image name (directory under the images dir).",
            autocompletion=_complete_image,
        ),
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Delete an image build context directory (and ALL its contents)."""
    ensure_root()
    _print_runtime_banner()
    img = ctx.config.images
    path = img.dir / name

    if not path.is_dir():
        err_console.print(f"[red]ERROR[/red] No such image build context: {path}")
        raise typer.Exit(code=2)

    console.print(f"\n[bold]Delete image build context[/bold] {path}/")
    console.print("  [yellow]This removes the directory and ALL its contents (Dockerfile + sources).[/yellow]")
    if not yes and not typer.confirm("\nDelete it?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    runner = CommandRunner(dry_run=False)
    try:
        runner.run(["rm", "-rf", str(path)])
    except CommandExecutionError as e:
        err_console.print(f"[red]ERROR[/red] Could not delete {path}: {e} (run with sudo?)")
        raise typer.Exit(code=2)
    console.print(f"\n[green]✓ Deleted {path}[/green]")


@image_app.command("list")
def image_list_cmd() -> None:
    """List image build contexts with their Dockerfile presence and compliance."""
    _print_runtime_banner()
    img = ctx.config.images

    subs = list_external_subdirs(img)
    if not subs:
        console.print(f"[dim]No image build contexts under {img.dir}.[/dim]")
        raise typer.Exit()

    findings = {
        f.path: f
        for f in audit_external_dir(
            ctx.config, img, "image_dir",
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
            file_name=DOCKERFILE_NAME,
        )
    }

    def _perms_cell(f: Optional[Finding]) -> Text:
        if f is None or f.severity is Severity.OK:
            return Text("✓ ok", style="green")
        if f.severity is Severity.DRIFT:
            return Text("✗ drift", style="yellow")
        return Text("! " + f.severity.value, style="magenta")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Image")
    table.add_column("Dockerfile")
    table.add_column("Perms")
    for path in subs:
        has_df = (path / DOCKERFILE_NAME).is_file()
        if not has_df:
            dockerfile = Text("—", style="dim")
        else:
            df_finding = findings.get(path / DOCKERFILE_NAME)
            dockerfile = Text("✓", style="green") if df_finding is None else _perms_cell(df_finding)
        table.add_row(path.name, dockerfile, _perms_cell(findings.get(path)))
    console.print(table)


def cli_main() -> None:  # pragma: no cover
    """Module-level entry point (also used by `python -m clixz`)."""
    app()


if __name__ == "__main__":  # pragma: no cover
    cli_main()
