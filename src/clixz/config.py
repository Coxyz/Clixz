"""Typed configuration loader for clixz.

Three rules, no ACLs
--------------------
v1 carried seven per-path rules and a POSIX ACL engine. The audit of 2026-08-29
retired both:

- the ``komodo`` ACL was decorative — Komodo Periphery runs as uid 0 with the
  Docker socket, so it already reads and writes everything;
- the ``dev`` ACL served code-server, which is not deployed;
- the ``docker:r`` ACL on ``.env`` had no reader either: the Docker daemon reads
  env files as root.

What is left is three rules over two axes — is it a directory, a file, or a
secret — which is the whole of what the audit found worth enforcing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from importlib.resources import files
from pathlib import Path

import yaml

from .rules import Policy, load_policy

# Where the config lives when nothing says otherwise, and therefore where the
# files clixz generates next to it (manifest, NPM snapshot) go by default.
DEFAULT_CONFIG_DIR = Path("/etc/clixz")

CONFIG_LOCATIONS: tuple[Path, ...] = (
    DEFAULT_CONFIG_DIR / "config.yaml",
    Path.home() / ".config" / "clixz" / "config.yaml",
)


def env(name: str, default: str = "") -> str:
    """Read a ``CLIXZ_``-prefixed environment variable."""
    return os.environ.get(f"CLIXZ_{name}", default)


@dataclass(frozen=True)
class CategoryConfig:
    user: str
    group: str

    @property
    def owner(self) -> str:
        return f"{self.user}:{self.group}"


@dataclass(frozen=True)
class RuleConfig:
    """Owner and mode expected on a path.

    ``owner`` overrides the category account (used by ``env``, which is
    ``root:root`` so a container running as the category user cannot read it).
    """

    mode: str
    owner: str | None = None


@dataclass(frozen=True)
class NpmConfig:
    """Where to find the Nginx Proxy Manager database, for ``clixz exposed``.

    Reading it needs root, and clixz degrades to a warning when it cannot. The
    point is not enforcement — it is that the audit found 24 proxy hosts where
    the service descriptors declared 9, and nothing in the system noticed.

    ``snapshot`` is a copy of the proxy hosts that root writes with
    ``clixz exposed --snapshot`` and anyone may read. It is how the unprivileged
    ``clixz-mcpd`` answers ``exposed`` without ever being given the database.
    """

    database: Path | None = None
    snapshot: Path | None = None


# Every rule, with its built-in default. A config may override any of them; one
# that omits a rule still works, which keeps `clixz check` usable on a host
# whose /etc/clixz/config.yaml has not been updated yet.
DEFAULT_RULES: dict[str, RuleConfig] = {
    # category/, service/, config/, data/ — the whole directory skeleton.
    "dir": RuleConfig(mode="750"),
    # compose.yaml, service.yaml, and anything else at the service root.
    "file": RuleConfig(mode="640"),
    # .env — secrets. root:root 600: the Docker daemon reads it as root, and no
    # other account has a reason to. This is the one control the audit found
    # still standing against an attacker already on the machine.
    "env": RuleConfig(mode="600", owner="root:root"),
}

RULE_NAMES = tuple(DEFAULT_RULES)


@dataclass(frozen=True)
class Config:
    root_dir: Path
    categories: dict[str, CategoryConfig]
    rules: dict[str, RuleConfig] = field(default_factory=lambda: dict(DEFAULT_RULES))
    exclude: list[str] = field(default_factory=list)
    manifest_path: Path | None = None
    images_dir: Path = Path("/opt/images")
    repos_dir: Path = Path("/opt/repos")
    npm: NpmConfig = field(default_factory=NpmConfig)
    # The directory config.yaml was read from; None for the bundled default.
    config_dir: Path | None = None
    # lint.yaml and ignore.yaml, read from config_dir.
    policy: Policy = field(default_factory=Policy)

    def category(self, name: str) -> CategoryConfig:
        if name not in self.categories:
            raise KeyError(
                f"Unknown category '{name}'. "
                f"Authorized: {', '.join(sorted(self.categories))}"
            )
        return self.categories[name]

    def rule(self, name: str) -> RuleConfig:
        return self.rules.get(name) or DEFAULT_RULES[name]

    @property
    def resolved_manifest_path(self) -> Path:
        # Next to the config, not inside a service: the manifest describes the
        # whole tree, and whichever container serves it mounts it from here.
        if self.manifest_path is not None:
            return self.manifest_path
        return (self.config_dir or DEFAULT_CONFIG_DIR) / "manifest.json"

    @property
    def resolved_npm_snapshot(self) -> Path:
        if self.npm.snapshot is not None:
            return self.npm.snapshot
        return (self.config_dir or DEFAULT_CONFIG_DIR) / "npm-hosts.json"


# ─── loading ─────────────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")
    return data


def _bundled_default() -> dict:
    resource = files("clixz").joinpath("default_config.yaml")
    return yaml.safe_load(resource.read_text(encoding="utf-8"))


def find_config_path(explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"Config not found: {explicit}")
        return explicit
    for candidate in CONFIG_LOCATIONS:
        if candidate.is_file():
            return candidate
    return None


def parse_config(raw: dict) -> Config:
    try:
        categories = {
            str(name): CategoryConfig(user=str(c["user"]), group=str(c["group"]))
            for name, c in raw["categories"].items()
        }
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"Invalid 'categories' section: {exc}") from exc

    rules = dict(DEFAULT_RULES)
    for name, r in (raw.get("rules") or {}).items():
        if name not in DEFAULT_RULES:
            continue  # reported by validate_config, not fatal here
        if not isinstance(r, dict) or "mode" not in r:
            raise ValueError(f"rules.{name} must be a mapping with a 'mode'")
        rules[str(name)] = RuleConfig(mode=str(r["mode"]), owner=r.get("owner"))

    exclude_raw = raw.get("exclude") or []
    if not isinstance(exclude_raw, list):
        raise ValueError("exclude must be a list of glob patterns")

    api = raw.get("api")
    manifest_path = (
        Path(str(api["manifest"]))
        if isinstance(api, dict) and api.get("manifest")
        else None
    )

    images = raw.get("images")
    images_dir = (
        Path(str(images["dir"]))
        if isinstance(images, dict) and images.get("dir")
        else Path("/opt/images")
    )

    repos = raw.get("repos")
    repos_dir = (
        Path(str(repos["dir"]))
        if isinstance(repos, dict) and repos.get("dir")
        else Path("/opt/repos")
    )

    root_dir = Path(str(raw["root_dir"]))
    npm_raw = raw.get("npm")
    # Without an `npm` section the database is looked for where this layout
    # puts it; `npm: {database: null}` is how a host without NPM says so.
    npm = NpmConfig(database=root_dir / "network" / "npm" / "data" / "app" / "database.sqlite")
    if isinstance(npm_raw, dict):
        npm = NpmConfig(
            database=Path(str(npm_raw["database"])) if npm_raw.get("database") else None,
            snapshot=Path(str(npm_raw["snapshot"])) if npm_raw.get("snapshot") else None,
        )

    return Config(
        root_dir=root_dir,
        categories=categories,
        rules=rules,
        exclude=[str(p) for p in exclude_raw],
        manifest_path=manifest_path,
        images_dir=images_dir,
        repos_dir=repos_dir,
        npm=npm,
    )


def load_config(explicit: Path | None = None) -> tuple[Config, Path | None]:
    """Load the config. ``source`` is None when the bundled default is used."""
    source = find_config_path(explicit)
    raw = _load_yaml(source) if source is not None else _bundled_default()
    config = parse_config(raw)
    if source is not None:
        config = replace(config, config_dir=source.parent, policy=load_policy(source.parent))
    return config, source


def load_raw_config(source: Path | None) -> dict:
    return _load_yaml(source) if source is not None else _bundled_default()


# ─── structural validation (for `clixz check`) ───────────────────────────────

KNOWN_TOP_LEVEL = {"root_dir", "categories", "rules", "exclude", "api", "images",
                   "repos", "npm"}

# Sections v1 understood and v2 does not. Naming them explicitly turns "unknown
# key" — which reads like a typo — into an actionable migration message.
RETIRED_KEYS = {
    "settings": "ACL principals are gone: v2 uses owner/mode only.",
    "komodo": "ACL principals are gone: Komodo Periphery runs as root already.",
    "dev": "`clixz dev` is gone: code-server is not deployed.",
}

# `repos` came back in 2.2 with a single key. What v1 stored under it (owner,
# mode, ACL, recursive) is still retired: /opt/repos is not audited.
RETIRED_REPOS_KEYS = ("owner", "mode", "acl", "recursive")

RETIRED_RULES = {
    "category_dir": "dir", "service_dir": "dir", "config_dir": "dir", "data_dir": "dir",
    "compose_file": "file", "service_file": "file", "spec_file": "file",
    "env_file": "env",
}


def validate_config(raw: dict) -> list[str]:
    """Return every structural problem found (empty list = OK).

    Deliberately exhaustive rather than fail-fast: a config with three mistakes
    should surface three messages, not force three round trips.
    """
    if not isinstance(raw, dict):
        return ["top-level YAML must be a mapping"]

    issues: list[str] = []

    if not str(raw.get("root_dir", "")).strip():
        issues.append("missing or empty 'root_dir'")

    categories = raw.get("categories")
    if not isinstance(categories, dict) or not categories:
        issues.append("'categories' must be a non-empty mapping")
    else:
        for name, c in categories.items():
            if not isinstance(c, dict) or not c.get("user") or not c.get("group"):
                issues.append(f"categories.{name} must define 'user' and 'group'")

    rules = raw.get("rules")
    if rules is not None and not isinstance(rules, dict):
        issues.append("'rules' must be a mapping")
    elif isinstance(rules, dict):
        for name, r in rules.items():
            if name in RETIRED_RULES:
                issues.append(
                    f"rules.{name} was retired in v2 — use rules.{RETIRED_RULES[name]}"
                )
                continue
            if name not in DEFAULT_RULES:
                issues.append(
                    f"unknown rule '{name}' (known: {', '.join(RULE_NAMES)})"
                )
            elif not isinstance(r, dict) or "mode" not in r:
                issues.append(f"rules.{name} is missing 'mode'")

    if raw.get("exclude") is not None and not isinstance(raw["exclude"], list):
        issues.append("'exclude' must be a list of glob patterns")

    npm = raw.get("npm")
    if npm is not None and not isinstance(npm, dict):
        issues.append("'npm' must be a mapping with a 'database' path")

    repos = raw.get("repos")
    if repos is not None and not isinstance(repos, dict):
        issues.append("'repos' must be a mapping with a 'dir' path")
    elif isinstance(repos, dict):
        for key in RETIRED_REPOS_KEYS:
            if key in repos:
                issues.append(f"repos.{key} was retired in v2 — /opt/repos is not audited, "
                              "only 'dir' is read")

    for key in raw:
        if key in RETIRED_KEYS:
            issues.append(f"'{key}' was retired in v2 — {RETIRED_KEYS[key]}")
        elif key not in KNOWN_TOP_LEVEL:
            issues.append(f"unknown top-level key '{key}'")

    return issues


def migrate_raw(raw: dict) -> dict:
    """Best-effort translation of a v1 config into the v2 shape.

    Only the parts that carry information forward: root_dir, categories,
    exclude, api.manifest, images.dir. The ACL sections are dropped rather than
    translated — they have no v2 equivalent, which is the point.
    """
    out: dict = {"root_dir": raw.get("root_dir", "/srv/docker")}
    if isinstance(raw.get("categories"), dict):
        out["categories"] = {
            str(n): {"user": c.get("user"), "group": c.get("group")}
            for n, c in raw["categories"].items()
            if isinstance(c, dict)
        }
    if raw.get("exclude"):
        out["exclude"] = list(raw["exclude"])

    old = raw.get("rules") or {}
    rules: dict[str, dict] = {}
    for v1_name, v2_name in (("service_dir", "dir"), ("compose_file", "file"),
                             ("env_file", "env")):
        r = old.get(v1_name)
        if isinstance(r, dict) and r.get("mode") and v2_name not in rules:
            rules[v2_name] = {"mode": str(r["mode"])}
    # The env rule keeps its owner override whatever the old config said: the
    # whole point of root:root is that it does not follow the category.
    rules.setdefault("env", {"mode": "600"})["owner"] = "root:root"
    out["rules"] = rules

    if isinstance(raw.get("api"), dict) and raw["api"].get("manifest"):
        out["api"] = {"manifest": raw["api"]["manifest"]}
    if isinstance(raw.get("images"), dict) and raw["images"].get("dir"):
        out["images"] = {"dir": raw["images"]["dir"]}
    return out
