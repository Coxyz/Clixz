"""Typed service specification, and generation of the canonical ``compose.yaml``.

A ``compose.yaml`` is code: Komodo deploys it while holding the Docker socket,
so a compose that reaches the daemon reaches root. Validating hand-written YAML
against a list of forbidden keys is a losing game — the list is never complete
(``privileged``, ``pid: host``, ``devices``, ``cap_add: SYS_MODULE``, a
top-level ``volumes`` entry with ``driver_opts.device: /``, an ``env_file``
pointing at *another* service's secrets, ``${...}`` interpolation that makes the
validated text differ from the deployed one…).

So this module does not validate YAML. It **generates** it, from a closed,
typed structure. What the structure cannot express simply cannot appear in the
output: there is no field for ``privileged``, none for host networking, none
for an arbitrary bind mount, and no way to name an ``env_file`` other than the
service's own. That turns "reject every hostile input" — unbounded — into
"accept a handful of scalars" — bounded.

The rendered layout follows the canonical model of ``instruction-compose.md``
§0. Any change there should be mirrored here.
"""

from __future__ import annotations

import grp
import json
import pwd
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .config import Config

# Networks a generated service may join. Both are external and host-scoped;
# ``network_mode`` is not expressible at all, so host networking is out of reach.
DEFAULT_NETWORKS = ("boxyz_network", "boxyz_macvlan")

# Only these two directories of the service tree can be bind-mounted. They are
# resolved server-side from the category/service, never from caller input, so a
# path cannot point anywhere else on the host.
MOUNTABLE = ("config", "data")

MAX_EXPOSE = 8
MAX_MOUNTS = 8
MAX_PIDS = 4096
MAX_MEM_MB = 4096

_IMAGE_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9._/-]*)"
    r"(?::(?P<tag>[A-Za-z0-9][A-Za-z0-9._-]*))?"
    r"(?:@(?P<digest>sha256:[a-f0-9]{64}))?$"
)
_TARGET_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
_MEM_RE = re.compile(r"^(?P<n>\d+)(?P<unit>[mg])$")
_CPUS_RE = re.compile(r"^\d+(\.\d{1,2})?$")


class SpecError(ValueError):
    """The specification is not acceptable. The message is caller-facing."""


@dataclass(frozen=True)
class Mount:
    """A bind mount, necessarily inside the service's own tree."""

    source: str          # "config" or "data"
    target: str          # absolute path inside the container
    read_only: bool = False


@dataclass(frozen=True)
class ServiceSpec:
    category: str
    service: str
    image: str
    expose: list[str] = field(default_factory=list)
    mounts: list[Mount] = field(default_factory=list)
    network: str = DEFAULT_NETWORKS[0]
    pids_limit: int = 256
    mem_limit: str = "256m"
    cpus: str = "0.50"
    tmpfs_size: str = "64m"
    depends_on: list[str] = field(default_factory=list)
    run_as_category_user: bool = True


# ─── validation ───────────────────────────────────────────────────────────────

def _check_image(image: str) -> str:
    if "$" in image:
        raise SpecError(
            "image must not contain '${...}': an interpolated value would make "
            "the deployed image differ from the validated one."
        )
    m = _IMAGE_RE.match(image)
    if not m:
        raise SpecError(f"Malformed image reference: {image!r}")
    tag, digest = m.group("tag"), m.group("digest")
    if not tag and not digest:
        raise SpecError(
            f"image {image!r} is not pinned. Give an explicit tag "
            "(nginx:1.27.3) or a digest (…@sha256:…)."
        )
    if tag == "latest":
        raise SpecError("image tag 'latest' is mutable and not allowed — pin a version.")
    return image


def _check_expose(expose: list[str]) -> list[str]:
    if len(expose) > MAX_EXPOSE:
        raise SpecError(f"Too many exposed ports (max {MAX_EXPOSE}).")
    out: list[str] = []
    for p in expose:
        try:
            port = int(str(p).strip())
        except (TypeError, ValueError):
            raise SpecError(f"Invalid port: {p!r} (an integer is expected).") from None
        if not 1 <= port <= 65535:
            raise SpecError(f"Port out of range: {port}.")
        out.append(str(port))
    return out


def _check_mounts(mounts: list[Mount]) -> list[Mount]:
    if len(mounts) > MAX_MOUNTS:
        raise SpecError(f"Too many mounts (max {MAX_MOUNTS}).")
    seen: set[str] = set()
    out: list[Mount] = []
    for m in mounts:
        if m.source not in MOUNTABLE:
            raise SpecError(
                f"Invalid mount source {m.source!r}. Only {', '.join(MOUNTABLE)} "
                "can be mounted — the host filesystem is not reachable."
            )
        if not _TARGET_RE.match(m.target) or ".." in m.target:
            raise SpecError(f"Invalid container path: {m.target!r} (absolute, no '..').")
        if m.target in seen:
            raise SpecError(f"Duplicate container path: {m.target}.")
        seen.add(m.target)
        # config/ is an input, written by a human and read by the container.
        # Forcing :ro here means the guarantee does not depend on the caller.
        out.append(Mount(m.source, m.target, read_only=True if m.source == "config" else m.read_only))
    return out


def _check_limits(spec: ServiceSpec) -> None:
    if not 1 <= spec.pids_limit <= MAX_PIDS:
        raise SpecError(f"pids_limit must be between 1 and {MAX_PIDS}.")
    m = _MEM_RE.match(spec.mem_limit.lower())
    if not m:
        raise SpecError("mem_limit must look like '256m' or '2g'.")
    mb = int(m.group("n")) * (1024 if m.group("unit") == "g" else 1)
    if not 1 <= mb <= MAX_MEM_MB:
        raise SpecError(f"mem_limit must not exceed {MAX_MEM_MB}m.")
    if not _CPUS_RE.match(spec.cpus):
        raise SpecError("cpus must look like '0.50' or '2'.")
    if not _MEM_RE.match(spec.tmpfs_size.lower()):
        raise SpecError("tmpfs_size must look like '64m'.")


def validate(spec: ServiceSpec, config: Config, *, networks: tuple[str, ...] = DEFAULT_NETWORKS) -> ServiceSpec:
    """Return a normalised spec, or raise :class:`SpecError`."""
    from .scaffold import validate_service_name  # local import: avoids a cycle

    if spec.category not in config.categories:
        raise SpecError(
            f"Unknown category {spec.category!r}. "
            f"Known: {', '.join(sorted(config.categories))}."
        )
    try:
        validate_service_name(spec.service)
        for dep in spec.depends_on:
            validate_service_name(dep)
    except ValueError as exc:
        raise SpecError(str(exc)) from None
    if spec.network not in networks:
        raise SpecError(
            f"Unknown network {spec.network!r}. Allowed: {', '.join(networks)}."
        )
    _check_limits(spec)
    return ServiceSpec(
        category=spec.category,
        service=spec.service,
        image=_check_image(spec.image),
        expose=_check_expose(spec.expose),
        mounts=_check_mounts(spec.mounts),
        network=spec.network,
        pids_limit=spec.pids_limit,
        mem_limit=spec.mem_limit.lower(),
        cpus=spec.cpus,
        tmpfs_size=spec.tmpfs_size.lower(),
        depends_on=list(spec.depends_on),
        run_as_category_user=spec.run_as_category_user,
    )


# ─── parsing from JSON/dict ───────────────────────────────────────────────────

_ALLOWED_KEYS = {
    "category", "service", "image", "expose", "mounts", "network",
    "pids_limit", "mem_limit", "cpus", "tmpfs_size", "depends_on",
    "run_as_category_user",
}

# Identity fields: they place the service in the tree, so a patch cannot move it.
_IMMUTABLE_KEYS = {"category", "service"}


def spec_from_dict(raw: Any) -> ServiceSpec:
    """Build a spec from a plain mapping, rejecting any unknown key.

    Rejecting unknown keys is what keeps the structure closed: a caller cannot
    smuggle ``privileged`` or ``volumes`` through by adding a field and hoping
    it reaches the renderer.
    """
    if not isinstance(raw, dict):
        raise SpecError("The specification must be a JSON/YAML object.")
    unknown = set(raw) - _ALLOWED_KEYS
    if unknown:
        raise SpecError(
            f"Unknown field(s): {', '.join(sorted(unknown))}. "
            f"Accepted: {', '.join(sorted(_ALLOWED_KEYS))}."
        )
    for required in ("category", "service", "image"):
        if not raw.get(required):
            raise SpecError(f"Missing required field: {required}.")

    mounts: list[Mount] = []
    for entry in raw.get("mounts") or []:
        if not isinstance(entry, dict):
            raise SpecError("Each mount must be an object {source, target, read_only}.")
        extra = set(entry) - {"source", "target", "read_only"}
        if extra:
            raise SpecError(f"Unknown mount field(s): {', '.join(sorted(extra))}.")
        mounts.append(Mount(
            source=str(entry.get("source", "")),
            target=str(entry.get("target", "")),
            read_only=bool(entry.get("read_only", False)),
        ))

    return ServiceSpec(
        category=str(raw["category"]),
        service=str(raw["service"]),
        image=str(raw["image"]),
        expose=[str(p) for p in (raw.get("expose") or [])],
        mounts=mounts,
        network=str(raw.get("network") or DEFAULT_NETWORKS[0]),
        pids_limit=int(raw.get("pids_limit", 256)),
        mem_limit=str(raw.get("mem_limit", "256m")),
        cpus=str(raw.get("cpus", "0.50")),
        tmpfs_size=str(raw.get("tmpfs_size", "64m")),
        depends_on=[str(d) for d in (raw.get("depends_on") or [])],
        run_as_category_user=bool(raw.get("run_as_category_user", True)),
    )


# ─── persistence ──────────────────────────────────────────────────────────────

SPEC_FILENAME = "spec.json"


def spec_to_dict(spec: ServiceSpec) -> dict[str, Any]:
    """The spec as a plain mapping, round-trippable through :func:`spec_from_dict`."""
    return {
        "category": spec.category,
        "service": spec.service,
        "image": spec.image,
        "expose": list(spec.expose),
        "mounts": [
            {"source": m.source, "target": m.target, "read_only": m.read_only}
            for m in spec.mounts
        ],
        "network": spec.network,
        "pids_limit": spec.pids_limit,
        "mem_limit": spec.mem_limit,
        "cpus": spec.cpus,
        "tmpfs_size": spec.tmpfs_size,
        "depends_on": list(spec.depends_on),
        "run_as_category_user": spec.run_as_category_user,
    }


def spec_json(spec: ServiceSpec) -> str:
    return json.dumps(spec_to_dict(spec), indent=2, ensure_ascii=False) + "\n"


def spec_path(config: Config, category: str, service: str) -> Path:
    return config.root_dir / category / service / SPEC_FILENAME


def load_spec(config: Config, category: str, service: str) -> ServiceSpec:
    """Read a service's stored spec. Raises :class:`SpecError` if unusable."""
    path = spec_path(config, category, service)
    if not path.is_file():
        raise SpecError(
            f"{category}/{service} has no {SPEC_FILENAME}: it was not generated "
            "from a spec, so it cannot be patched. Edit its compose.yaml by hand, "
            "or re-create the service from a spec."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SpecError(f"Unreadable {path}: {exc}") from None
    return spec_from_dict(raw)


def apply_patch(spec: ServiceSpec, patch: Any) -> ServiceSpec:
    """Merge a partial mapping into an existing spec.

    Semantics are deliberately blunt: a field present in the patch **replaces**
    the current value outright, lists included. Deep-merging a list of mounts
    would raise questions with no good answer (match on target? on index?) and
    make the result hard to predict — the caller can always resend the full
    list, which is short.

    ``category`` and ``service`` are not patchable: renaming or moving a service
    is a different operation entirely (its directory, ownership and ACLs would
    all have to move), and silently accepting it here would write a compose that
    no longer matches the tree it lives in.
    """
    if not isinstance(patch, dict):
        raise SpecError("The patch must be a JSON object.")
    if not patch:
        raise SpecError("Empty patch: nothing to change.")

    unknown = set(patch) - _ALLOWED_KEYS
    if unknown:
        raise SpecError(
            f"Unknown field(s): {', '.join(sorted(unknown))}. "
            f"Patchable: {', '.join(sorted(_ALLOWED_KEYS - _IMMUTABLE_KEYS))}."
        )
    frozen = _IMMUTABLE_KEYS & set(patch)
    for key in sorted(frozen):
        if str(patch[key]) != str(getattr(spec, key)):
            raise SpecError(
                f"Field '{key}' cannot be changed by a patch (currently "
                f"{getattr(spec, key)!r}). Moving or renaming a service is a "
                "separate operation."
            )

    merged = spec_to_dict(spec)
    merged.update({k: v for k, v in patch.items() if k not in _IMMUTABLE_KEYS})
    return spec_from_dict(merged)


# ─── rendering ────────────────────────────────────────────────────────────────

class _Quoted(str):
    """A string that must survive as a string in the YAML output."""


def _represent_quoted(dumper: yaml.SafeDumper, data: _Quoted) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="'")


class _Dumper(yaml.SafeDumper):
    pass


_Dumper.add_representer(_Quoted, _represent_quoted)


def _category_uid_gid(config: Config, category: str) -> _Quoted | None:
    cat = config.category(category)
    try:
        # Quoted: an unquoted "988:59" is read as a YAML 1.1 sexagesimal integer
        # (59339), which would silently run the container under the wrong uid.
        return _Quoted(f"{pwd.getpwnam(cat.user).pw_uid}:{grp.getgrnam(cat.group).gr_gid}")
    except KeyError:
        return None


def render_compose(spec: ServiceSpec, config: Config) -> str:
    """Render the canonical compose.yaml for a validated spec."""
    svc_dir = config.root_dir / spec.category / spec.service
    body: dict[str, Any] = {
        "image": spec.image,
        "container_name": spec.service,
        "restart": "unless-stopped",
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "pids_limit": spec.pids_limit,
        "mem_limit": spec.mem_limit,
        "cpus": spec.cpus,
        "tmpfs": [f"/tmp:rw,noexec,nosuid,size={spec.tmpfs_size}"],
        "networks": [spec.network],
    }
    if spec.run_as_category_user:
        user = _category_uid_gid(config, spec.category)
        if user:
            body["user"] = user
    if spec.expose:
        body["expose"] = list(spec.expose)
    # Always the service's own .env, never a path the caller chose: this is the
    # quiet exfiltration path (env_file pointing at another service's secrets,
    # read by the daemon as root).
    body["env_file"] = [".env"]
    if spec.mounts:
        body["volumes"] = [
            f"{svc_dir / m.source}:{m.target}" + (":ro" if m.read_only else "")
            for m in spec.mounts
        ]
    if spec.depends_on:
        body["depends_on"] = list(spec.depends_on)
    body["logging"] = {
        "driver": "json-file",
        "options": {"max-size": "10m", "max-file": "3"},
    }

    doc = {
        "services": {spec.service: body},
        "networks": {spec.network: {"external": True}},
    }
    header = (
        f"# Generated by coxyz from a typed specification — do not hand-edit.\n"
        f"# Service: {spec.category}/{spec.service}\n"
    )
    return header + yaml.dump(
        doc, Dumper=_Dumper, sort_keys=False,
        default_flow_style=False, allow_unicode=True,
    )
