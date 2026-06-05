"""Logic for the ``dev`` command: mount services into code-server for editing.

Two independent, side-effect-free helpers live here so they can be unit-tested
without Typer or a real filesystem:

* the **compose editor** — manages a single marker-delimited block inside the
  code-server ``volumes:`` list, leaving every other byte (comments, order,
  indentation) untouched. The block is the source of truth for which services
  are dev-enabled.
* the **ACL command builders** — the exact ``setfacl`` argv that grant/revoke a
  group's recursive access (existing children + a default ACL for new files).
"""

from __future__ import annotations

from pathlib import Path

from .system import normalize_perms

# A service is identified by its (category, service) pair.
Service = tuple[str, str]

MARKER_BEGIN = "# >>> coxyz dev (managed — do not edit by hand) >>>"
MARKER_END = "# <<< coxyz dev (managed) <<<"


# ─── Principal resolution ─────────────────────────────────────────────────────

def resolve_principal(principals: dict, wanted: str):
    """Find a principal by its dict key, falling back to its ``.name``.

    Returns the principal (a ``PrincipalConfig``) or ``None``. Matching by name
    too means ``principal: dev`` and ``principal: boxyz_dev`` both resolve to a
    ``dev: {name: boxyz_dev}`` principal.
    """
    if wanted in principals:
        return principals[wanted]
    return next((p for p in principals.values() if p.name == wanted), None)


# ─── Mount paths ──────────────────────────────────────────────────────────────

def mount_targets(category: str, service: str, mount_base: str) -> list[str]:
    """The two in-container paths a dev-enabled service is mounted at."""
    base = f"{mount_base}/{category}/{service}"
    return [f"{base}/config", f"{base}/data"]


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _service_from_host(host: str, root_dir: Path) -> Service | None:
    """Map a host path like ``<root>/apps/nginx/config`` to ``("apps", "nginx")``."""
    try:
        parts = Path(host).relative_to(root_dir).parts
    except ValueError:
        return None
    return (parts[0], parts[1]) if len(parts) >= 2 else None


# ─── Reading the managed block ────────────────────────────────────────────────

def read_enabled(text: str, root_dir: Path, mount_base: str) -> list[Service]:
    """Return the dev-enabled services declared in the managed block (sorted)."""
    lines = text.split("\n")
    span = _block_span(lines)
    if span is None:
        return []
    begin, end = span
    found: set[Service] = set()
    for line in lines[begin + 1:end]:
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        host = stripped[2:].strip().split(":", 1)[0]
        svc = _service_from_host(host, root_dir)
        if svc is not None:
            found.add(svc)
    return sorted(found)


# ─── Rewriting the managed block ──────────────────────────────────────────────

def add_service(text: str, category: str, service: str, root_dir: Path, mount_base: str) -> str:
    enabled = set(read_enabled(text, root_dir, mount_base))
    enabled.add((category, service))
    return _set_enabled(text, enabled, root_dir, mount_base)


def remove_service(text: str, category: str, service: str, root_dir: Path, mount_base: str) -> str:
    enabled = set(read_enabled(text, root_dir, mount_base))
    enabled.discard((category, service))
    return _set_enabled(text, enabled, root_dir, mount_base)


def _block_span(lines: list[str]) -> tuple[int, int] | None:
    """Indices of the begin/end marker lines, or None if there is no block."""
    begin = end = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s == MARKER_BEGIN:
            begin = i
        elif s == MARKER_END:
            end = i
    if begin is None or end is None or end < begin:
        return None
    return begin, end


def _strip_block(lines: list[str]) -> list[str]:
    """Drop the managed block (and the one blank separator we add before it)."""
    span = _block_span(lines)
    if span is None:
        return lines
    begin, end = span
    if begin > 0 and lines[begin - 1].strip() == "":
        begin -= 1
    return lines[:begin] + lines[end + 1:]


def _volumes_tail(lines: list[str]) -> tuple[int, str]:
    """Find where to splice the block: (index of last volumes entry, item indent).

    The volumes block is the run of blank / more-indented lines after the
    ``volumes:`` key. We insert right after its last non-blank line.
    """
    vi = next((i for i, l in enumerate(lines) if l.strip() == "volumes:"), None)
    if vi is None:
        raise ValueError("no 'volumes:' block found in compose file")
    base_indent = _indent_of(lines[vi])
    last = vi
    item_indent: str | None = None
    for i in range(vi + 1, len(lines)):
        line = lines[i]
        if line.strip() == "":
            continue
        if _indent_of(line) <= base_indent:
            break
        last = i
        if item_indent is None and line.lstrip(" ").startswith("- "):
            item_indent = " " * _indent_of(line)
    return last, (item_indent if item_indent is not None else " " * (base_indent + 2))


def _block_lines(services: list[Service], root_dir: Path, mount_base: str, indent: str) -> list[str]:
    out = [f"{indent}{MARKER_BEGIN}"]
    for category, service in sorted(services):
        host = f"{root_dir.as_posix()}/{category}/{service}"
        mnt = f"{mount_base}/{category}/{service}"
        out.append(f"{indent}- {host}/config:{mnt}/config")
        out.append(f"{indent}- {host}/data:{mnt}/data")
    out.append(f"{indent}{MARKER_END}")
    return out


def _set_enabled(text: str, services: set[Service], root_dir: Path, mount_base: str) -> str:
    had_final_nl = text.endswith("\n")
    lines = text.split("\n")
    if had_final_nl and lines and lines[-1] == "":
        lines = lines[:-1]

    lines = _strip_block(lines)
    if services:
        last, indent = _volumes_tail(lines)
        block = [""] + _block_lines(sorted(services), root_dir, mount_base, indent)
        lines = lines[:last + 1] + block + lines[last + 1:]

    out = "\n".join(lines)
    return out + "\n" if had_final_nl else out


# ─── ACL command builders ─────────────────────────────────────────────────────

def _acl_qualifier(kind: str, name: str) -> str:
    """The ``u:<name>`` or ``g:<name>`` qualifier for a principal."""
    return f"{'u' if kind == 'user' else 'g'}:{name}"


def _recursive_token(kind: str, name: str, perms: str) -> str:
    """e.g. ``u:boxyz_dev:rwX`` — execute as X so files never become executable."""
    present = normalize_perms(perms)
    sym = "".join(("X" if c == "x" else c) for c in ("r", "w", "x") if c in present)
    return f"{_acl_qualifier(kind, name)}:{sym}"


def acl_enable_cmds(paths: list[Path], kind: str, name: str, perms: str) -> list[list[str]]:
    """Grant the principal recursive access on each path: existing tree + default ACL."""
    token = _recursive_token(kind, name, perms)
    cmds: list[list[str]] = []
    for path in paths:
        cmds.append(["setfacl", "-R", "-m", token, str(path)])
        cmds.append(["setfacl", "-dR", "-m", token, str(path)])
    return cmds


def acl_disable_cmds(paths: list[Path], kind: str, name: str) -> list[list[str]]:
    """Revoke ONLY this principal's entry (access + default), recursively; keep others."""
    qualifier = _acl_qualifier(kind, name)
    cmds: list[list[str]] = []
    for path in paths:
        cmds.append(["setfacl", "-R", "-x", qualifier, str(path)])
        cmds.append(["setfacl", "-dR", "-x", qualifier, str(path)])
    return cmds
