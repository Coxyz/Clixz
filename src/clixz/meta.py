"""Service descriptors (``service.yaml``): parse, validate, scaffold, aggregate.

Every service may carry a ``service.yaml`` at its root, next to ``compose.yaml``.
It describes how the service is presented on the clixz dashboard — display name,
icon, short description, public/visibility flag — plus richer, **non-sensitive**
detail shown in the front-end popup (summary, features, internal ports, related
services, tech stack).

``clixz manifest`` reads every descriptor, validates it, and aggregates the
**public** ones into a single JSON file that the API serves (and the dashboard
renders). Private services (``public: false``) are excluded entirely — they
never reach the manifest, so nothing about them leaks to the front-end.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import Config
from .policy import is_excluded_path, list_services

SERVICE_FILENAME = "service.yaml"
MANIFEST_SCHEMA = 1

# Status presentation lives client-side; ``kind`` only drives which grid the
# card lands in ("app" = has a web UI, "infra" = internal/no-link).
_KINDS = ("app", "infra")

# Detail keys we recognise. Unknown keys are tolerated (warned, not rejected),
# so the descriptor format can grow without breaking older CLIs.
_KNOWN_DETAIL_KEYS = {"summary", "features", "ports", "depends_on", "tech", "notes", "links"}


@dataclass
class ServiceMeta:
    """A validated service descriptor, ready to serialise into the manifest."""

    key: str                      # stable id = service directory name
    category: str
    service: str
    name: str
    icon: str
    description: str
    public: bool
    kind: str                     # "app" | "infra"
    container: str                # Komodo/Docker container name for live status
    url: str | None               # public URL, or None for internal services
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        """The entry exposed in the manifest (and thus the API). No secrets here."""
        return {
            "key": self.key,
            "category": self.category,
            "name": self.name,
            "icon": self.icon,
            "description": self.description,
            "kind": self.kind,
            "container": self.container,
            "url": self.url,
            "tags": list(self.tags),
            "details": self.details,
        }


def _as_str_list(value: Any) -> list[str] | None:
    if value is None:
        return []
    if isinstance(value, list) and all(not isinstance(v, (dict, list)) for v in value):
        return [str(v) for v in value]
    return None


def parse_meta(
    raw: Any, category: str, service: str,
) -> tuple[ServiceMeta | None, list[str]]:
    """Parse + validate a raw ``service.yaml`` mapping.

    Returns ``(meta, issues)``. ``meta`` is ``None`` when a hard error makes the
    descriptor unusable (missing/blank required field, wrong type); ``issues``
    always lists every problem found (including soft warnings).
    """
    issues: list[str] = []
    if not isinstance(raw, dict):
        return None, [f"{SERVICE_FILENAME} must be a mapping"]

    def req_str(keyname: str) -> str | None:
        val = raw.get(keyname)
        if val is None or (isinstance(val, str) and not val.strip()):
            issues.append(f"missing required field '{keyname}'")
            return None
        if not isinstance(val, (str, int, float)):
            issues.append(f"'{keyname}' must be a string")
            return None
        return str(val).strip()

    name = req_str("name")
    icon = req_str("icon")
    description = req_str("description")

    public_raw = raw.get("public")
    if not isinstance(public_raw, bool):
        issues.append("'public' must be a boolean (true/false)")
        public = False
    else:
        public = public_raw

    url_raw = raw.get("url")
    url: str | None = None
    if url_raw is not None:
        if not isinstance(url_raw, str) or not url_raw.strip():
            issues.append("'url' must be a non-empty string when set")
        else:
            url = url_raw.strip()

    container_raw = raw.get("container")
    if container_raw is not None and (not isinstance(container_raw, str) or not container_raw.strip()):
        issues.append("'container' must be a non-empty string when set")
        container = service
    else:
        container = str(container_raw).strip() if container_raw else service

    kind_raw = raw.get("kind")
    if kind_raw is None:
        kind = "app" if url else "infra"
    elif kind_raw in _KINDS:
        kind = str(kind_raw)
    else:
        issues.append(f"'kind' must be one of {_KINDS}, got {kind_raw!r}")
        kind = "app" if url else "infra"

    tags = _as_str_list(raw.get("tags"))
    if tags is None:
        issues.append("'tags' must be a list of strings")
        tags = []

    details_raw = raw.get("details")
    details: dict[str, Any] = {}
    if details_raw is not None:
        if not isinstance(details_raw, dict):
            issues.append("'details' must be a mapping")
        else:
            details = _validate_details(details_raw, issues)

    # Hard errors → unusable descriptor.
    if name is None or icon is None or description is None or not isinstance(public_raw, bool):
        return None, issues

    meta = ServiceMeta(
        key=service, category=category, service=service,
        name=name, icon=icon, description=description, public=public,
        kind=kind, container=container, url=url, tags=tags, details=details,
    )
    return meta, issues


def _validate_details(details_raw: dict, issues: list[str]) -> dict[str, Any]:
    """Lightly validate the optional ``details`` block; drop only bad entries."""
    out: dict[str, Any] = {}
    for keyname, val in details_raw.items():
        if keyname not in _KNOWN_DETAIL_KEYS:
            issues.append(f"details: unknown key '{keyname}' (ignored)")
            continue
        if keyname in ("summary", "tech", "notes"):
            if isinstance(val, (str, int, float)):
                out[keyname] = str(val)
            else:
                issues.append(f"details.{keyname} must be a string")
        elif keyname in ("features", "ports", "depends_on"):
            lst = _as_str_list(val)
            if lst is None:
                issues.append(f"details.{keyname} must be a list of strings")
            else:
                out[keyname] = lst
        elif keyname == "links":
            links = _validate_links(val, issues)
            if links is not None:
                out[keyname] = links
    return out


def _validate_links(val: Any, issues: list[str]) -> list[dict[str, str]] | None:
    if not isinstance(val, list):
        issues.append("details.links must be a list of {label, url} mappings")
        return None
    out: list[dict[str, str]] = []
    for entry in val:
        if (isinstance(entry, dict) and isinstance(entry.get("label"), str)
                and isinstance(entry.get("url"), str)):
            out.append({"label": entry["label"], "url": entry["url"]})
        else:
            issues.append("details.links entries must be {label, url} mappings")
    return out


# ─── Scaffolding ──────────────────────────────────────────────────────────────

def scaffold_template(category: str, service: str) -> str:
    """A commented ``service.yaml`` template for a freshly created service."""
    title = service.replace("-", " ").replace("_", " ").title()
    return f"""\
# ─────────────────────────────────────────────────────────────────────────────
# service.yaml — clixz service descriptor ({category}/{service})
#
# Aggregated by `clixz manifest` and served (when public) at
# https://api.clixz.fr/api/services for the dashboard.
# Put only NON-SENSITIVE information here. Internal docker ports are fine.
# ─────────────────────────────────────────────────────────────────────────────
schema: 1

name: "{title}"                 # display name on the dashboard
icon: "📦"                       # emoji or single glyph
description: "TODO: short one-line description."
public: false                   # true = exposed by the API; false = hidden entirely

# kind: app | infra   (optional — defaults to "app" when a url is set, else "infra")
# container: {service}           # Komodo/Docker container name (defaults to "{service}")
# url: "https://{service}.clixz.fr"   # public link; omit for internal services
# tags: [example]

details:
  summary: "TODO: what this service does, in a sentence or two."
  features:
    - "TODO: notable capability"
  # ports listed here stay internal to docker — safe to expose:
  ports:
    - "TODO (e.g. 8080 interne)"
  depends_on: []                # other service keys this one relies on
  tech: "TODO: stack / image"
"""


# ─── Manifest aggregation ─────────────────────────────────────────────────────

@dataclass
class ManifestResult:
    manifest: dict[str, Any]
    errors: list[str]      # invalid descriptors (block a clean build)
    warnings: list[str]    # missing descriptors / soft issues
    public_count: int
    private_count: int


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_manifest(config: Config) -> ManifestResult:
    """Scan every service, validate its descriptor, aggregate the public ones."""
    services: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    public_count = 0
    private_count = 0

    for cat, svc, path in list_services(config):
        descriptor = path / SERVICE_FILENAME
        if is_excluded_path(config, descriptor):
            continue
        if not descriptor.is_file():
            warnings.append(f"{cat}/{svc}: no {SERVICE_FILENAME}")
            continue
        try:
            raw = yaml.safe_load(descriptor.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{cat}/{svc}: cannot read {SERVICE_FILENAME}: {exc}")
            continue

        meta, issues = parse_meta(raw, cat, svc)
        for issue in issues:
            (errors if meta is None else warnings).append(f"{cat}/{svc}: {issue}")
        if meta is None:
            continue
        if meta.public:
            services.append(meta.to_public_dict())
            public_count += 1
        else:
            private_count += 1

    services.sort(key=lambda s: (0 if s["kind"] == "app" else 1, s["name"].lower()))
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "generated_at": _iso_now(),
        "services": services,
    }
    return ManifestResult(
        manifest=manifest, errors=errors, warnings=warnings,
        public_count=public_count, private_count=private_count,
    )


def manifest_json(manifest: dict[str, Any]) -> str:
    """Serialise a manifest to pretty JSON with a trailing newline."""
    return json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
