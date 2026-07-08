"""Typed configuration loader for coxyz."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Literal

import yaml

PrincipalKind = Literal["group", "user"]
AclPerms = Literal["rx", "rw", "rwx", "x"]


@dataclass(frozen=True)
class PrincipalConfig:
    name: str
    kind: PrincipalKind


@dataclass(frozen=True)
class SettingsConfig:
    principals: dict[str, PrincipalConfig]


@dataclass(frozen=True)
class CategoryConfig:
    user: str
    group: str

    @property
    def owner_spec(self) -> str:
        return f"{self.user}:{self.group}"


@dataclass(frozen=True)
class RuleConfig:
    """Rule applied to a path (directory or file)."""

    mode: str  # octal as string e.g. "750"
    acl: dict[str, AclPerms] | None = None
    owner: str | None = None  # "user:group" override; None = use category owner
    audit_only: bool = False
    # When True, each named ACL entry is also (re)applied recursively to the
    # directory's existing contents, plus as a default ACL so new children
    # inherit it. Only meaningful alongside `acl`; ignored on files.
    recursive: bool = False


@dataclass(frozen=True)
class DevConfig:
    """Settings for the ``dev`` command (services editable via code-server)."""

    compose: Path        # code-server compose file to edit
    principal: str       # key in settings.principals (the code-server group)
    perms: str = "rwx"   # ACL perms granted recursively (execute as X on dirs)
    mount_base: str = "/workspace/services"  # container path prefix for mounts


_DEFAULT_DEV = DevConfig(
    compose=Path("/srv/docker/apps/code-boxyz/compose.yaml"),
    principal="boxyz_dev",
)


@dataclass(frozen=True)
class ExternalDirConfig:
    """A directory of subdirectories coxyz manages outside ``root_dir``.

    Used for ``images`` (self-built image build contexts under ``/opt/images``)
    and ``repos`` (source repos under ``/opt/repos``). Each immediate
    subdirectory (``<dir>/<name>/``) is brought to ``owner``/``mode``. The
    convention: owned by the dev principal (editable via code-server), and
    world-readable so Komodo Periphery can read the build context to build.
    """

    dir: Path
    owner: str = "boxyz_dev:boxyz_dev"   # "user:group" for each subdirectory
    mode: str = "775"                    # group writes (devs), others read (builder)
    acl: dict[str, AclPerms] | None = None  # optional named ACL, like a rule's
    recursive: bool = False  # apply `acl` recursively to existing subdir contents
    # Optional rule for the build file inside each subdirectory (the Dockerfile,
    # for images). When set, `image add` applies it and `check`/`apply` enforce
    # it; when None the Dockerfile keeps its legacy owner/mode and isn't audited.
    dockerfile: RuleConfig | None = None


_DEFAULT_IMAGES = ExternalDirConfig(dir=Path("/opt/images"))
_DEFAULT_REPOS = ExternalDirConfig(dir=Path("/opt/repos"))


# Built-in rule defaults used when a config predates a newer rule. This keeps
# coxyz working against an existing /etc/coxyz/config.yaml that has not yet been
# updated with the rule (e.g. ``service_file`` introduced for ``service.yaml``).
# ``service.yaml`` is non-sensitive presentation metadata: owner rw, group r.
_BUILTIN_RULE_DEFAULTS: dict[str, "RuleConfig"] = {
    "service_file": RuleConfig(mode="640"),
}


@dataclass(frozen=True)
class Config:
    root_dir: Path
    settings: SettingsConfig
    categories: dict[str, CategoryConfig]
    rules: dict[str, RuleConfig]
    exclude: list[str]
    dev: DevConfig = _DEFAULT_DEV
    images: ExternalDirConfig = _DEFAULT_IMAGES
    repos: ExternalDirConfig = _DEFAULT_REPOS
    manifest_path: Path | None = None

    def category(self, name: str) -> CategoryConfig:
        if name not in self.categories:
            raise KeyError(
                f"Unknown category '{name}'. "
                f"Authorized: {', '.join(sorted(self.categories))}"
            )
        return self.categories[name]

    def rule(self, name: str) -> RuleConfig:
        if name not in self.rules:
            raise KeyError(f"Missing rule '{name}' in config")
        return self.rules[name]

    def rule_or_default(self, name: str) -> RuleConfig:
        """Like :meth:`rule` but falls back to a built-in default when absent.

        Lets newer rules (e.g. ``service_file``) work against an older config.
        """
        if name in self.rules:
            return self.rules[name]
        if name in _BUILTIN_RULE_DEFAULTS:
            return _BUILTIN_RULE_DEFAULTS[name]
        raise KeyError(f"Missing rule '{name}' in config (no built-in default)")

    @property
    def resolved_manifest_path(self) -> Path:
        """Where ``coxyz manifest`` writes the aggregated services manifest.

        Defaults to the coxyz-api service's data directory so it can be mounted
        read-only into the API container.
        """
        if self.manifest_path is not None:
            return self.manifest_path
        return self.root_dir / "apps" / "api" / "data" / "manifest.json"


# ─── Loading ────────────────────────────────────────────────────────────

DEFAULT_CONFIG_LOCATIONS: tuple[Path, ...] = (
    Path("/etc/coxyz/config.yaml"),
    Path.home() / ".config" / "coxyz" / "config.yaml",
)


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")
    return data


def _load_bundled_default() -> dict:
    """Load the default config bundled with the package."""
    resource = files("coxyz").joinpath("default_config.yaml")
    return yaml.safe_load(resource.read_text(encoding="utf-8"))


def _parse_settings(raw: dict) -> SettingsConfig:
    if "settings" in raw:
        settings_raw = raw["settings"]
        principals_raw = settings_raw.get("principals")
        if not isinstance(principals_raw, dict) or not principals_raw:
            raise ValueError("settings.principals must be a non-empty mapping")
        principals: dict[str, PrincipalConfig] = {}
        for key, entry in principals_raw.items():
            if not isinstance(entry, dict):
                raise ValueError(f"settings.principals.{key} must be a mapping")
            name = str(entry["name"])
            kind = entry["kind"]
            if kind not in ("group", "user"):
                raise ValueError(
                    f"settings.principals.{key}.kind must be 'group' or 'user', got {kind!r}"
                )
            principals[str(key)] = PrincipalConfig(name=name, kind=kind)
        return SettingsConfig(principals=principals)

    # Backward-compatible shim for old 'komodo' config
    if "komodo" in raw:
        komodo = raw["komodo"]
        kind = komodo["kind"]
        if kind not in ("group", "user"):
            raise ValueError(f"komodo.kind must be 'group' or 'user', got {kind!r}")
        return SettingsConfig(
            principals={
                "komodo": PrincipalConfig(name=str(komodo["name"]), kind=kind)
            }
        )

    raise ValueError("Missing required key in config: settings (or legacy komodo)")


def _parse_acl(
    acl_raw: object,
    settings: SettingsConfig,
    label: str,
) -> dict[str, AclPerms] | None:
    """Parse a named-ACL mapping (``{principal: perms}``) shared by rules and
    external dirs. ``label`` is the config path used in error messages, e.g.
    ``"rules.config_dir"`` or ``"images"``.
    """
    if acl_raw is None:
        return None
    if isinstance(acl_raw, str):
        if "komodo" not in settings.principals:
            raise ValueError(f"{label}.acl uses legacy string but no 'komodo' principal")
        return {"komodo": acl_raw}
    if not isinstance(acl_raw, dict):
        raise ValueError(f"{label}.acl must be a mapping or null")

    acl: dict[str, AclPerms] = {}
    for principal_name, perms in acl_raw.items():
        if principal_name not in settings.principals:
            raise ValueError(
                f"{label}.acl references unknown principal '{principal_name}'"
            )
        if perms is None:
            raise ValueError(
                f"{label}.acl.{principal_name} must be a permission string"
            )
        acl[str(principal_name)] = str(perms)
    return acl


def _parse_dev(raw: dict) -> DevConfig:
    """Parse the optional ``dev`` section, falling back to defaults.

    The principal is validated lazily by the ``dev`` command (not here), so an
    existing config without a ``boxyz_dev`` principal still loads fine.
    """
    d = raw.get("dev")
    if not isinstance(d, dict):
        return _DEFAULT_DEV
    return DevConfig(
        compose=Path(str(d.get("compose", _DEFAULT_DEV.compose))),
        principal=str(d.get("principal", _DEFAULT_DEV.principal)),
        perms=str(d.get("perms", _DEFAULT_DEV.perms)),
        mount_base=str(d.get("mount_base", _DEFAULT_DEV.mount_base)),
    )


def _parse_external_dir(
    raw: dict, key: str, default: ExternalDirConfig, settings: SettingsConfig,
) -> ExternalDirConfig:
    """Parse an optional ``images``/``repos`` section, falling back to defaults."""
    d = raw.get(key)
    if not isinstance(d, dict):
        return default
    df_raw = d.get("dockerfile")
    dockerfile: RuleConfig | None = None
    if isinstance(df_raw, dict):
        dockerfile = RuleConfig(
            mode=str(df_raw.get("mode", "664")),
            acl=_parse_acl(df_raw.get("acl"), settings, f"{key}.dockerfile"),
            owner=df_raw.get("owner"),
            recursive=bool(df_raw.get("recursive", False)),
        )
    return ExternalDirConfig(
        dir=Path(str(d.get("dir", default.dir))),
        owner=str(d.get("owner", default.owner)),
        mode=str(d.get("mode", default.mode)),
        acl=_parse_acl(d.get("acl"), settings, key),
        recursive=bool(d.get("recursive", False)),
        dockerfile=dockerfile,
    )


def _parse_config(raw: dict) -> Config:
    try:
        settings = _parse_settings(raw)

        categories = {
            name: CategoryConfig(user=str(c["user"]), group=str(c["group"]))
            for name, c in raw["categories"].items()
        }

        rules: dict[str, RuleConfig] = {}
        for name, r in raw["rules"].items():
            rules[name] = RuleConfig(
                mode=str(r["mode"]),
                acl=_parse_acl(r.get("acl"), settings, f"rules.{name}"),
                owner=r.get("owner"),
                audit_only=bool(r.get("audit_only", False)),
                recursive=bool(r.get("recursive", False)),
            )

        exclude_raw = raw.get("exclude", [])
        if not isinstance(exclude_raw, list):
            raise ValueError("exclude must be a list of glob patterns")

        api_raw = raw.get("api")
        manifest_path: Path | None = None
        if isinstance(api_raw, dict) and api_raw.get("manifest"):
            manifest_path = Path(str(api_raw["manifest"]))

        return Config(
            root_dir=Path(raw["root_dir"]),
            settings=settings,
            categories=categories,
            rules=rules,
            exclude=[str(p) for p in exclude_raw],
            dev=_parse_dev(raw),
            images=_parse_external_dir(raw, "images", _DEFAULT_IMAGES, settings),
            repos=_parse_external_dir(raw, "repos", _DEFAULT_REPOS, settings),
            manifest_path=manifest_path,
        )
    except KeyError as e:
        raise ValueError(f"Missing required key in config: {e}") from e


def find_config_path(explicit: Path | None = None) -> Path | None:
    """Return the first existing config path, or None if only the bundled default is used."""
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"Config not found: {explicit}")
        return explicit
    for candidate in DEFAULT_CONFIG_LOCATIONS:
        if candidate.is_file():
            return candidate
    return None


def load_config(explicit: Path | None = None) -> tuple[Config, Path | None]:
    """Load config; returns (config, source_path). source_path is None if using bundled defaults."""
    source = find_config_path(explicit)
    raw = _load_yaml(source) if source is not None else _load_bundled_default()
    return _parse_config(raw), source


def load_raw_config(source: Path | None) -> dict:
    """Read the raw config mapping for ``source`` (or the bundled default)."""
    return _load_yaml(source) if source is not None else _load_bundled_default()


# ─── Structural validation (for `coxyz check`) ──────────────────────────────

# Top-level keys coxyz understands. Anything else is flagged as a likely typo
# or a section indented into the wrong place.
_KNOWN_TOP_LEVEL = {
    "root_dir", "settings", "komodo", "categories", "rules", "exclude",
    "dev", "api", "images", "repos",
}
_REQUIRED_RULES = {
    "category_dir", "service_dir", "compose_file", "config_dir", "data_dir", "env_file",
}


def validate_config(raw: dict) -> list[str]:
    """Return human-readable structural problems in a raw config (empty list = OK).

    This is intentionally lenient and exhaustive: it collects *every* issue it
    can find (rather than failing on the first) so ``coxyz check`` can report
    them all — missing keys, bad values, and sections nested in the wrong place.
    """
    if not isinstance(raw, dict):
        return ["top-level YAML must be a mapping"]

    issues: list[str] = []

    if "root_dir" not in raw:
        issues.append("missing 'root_dir'")
    elif not str(raw["root_dir"]).strip():
        issues.append("'root_dir' is empty")

    principals: dict = {}
    settings = raw.get("settings")
    if not isinstance(settings, dict):
        if "komodo" not in raw:
            issues.append("missing 'settings' (with a 'principals' mapping)")
    else:
        raw_principals = settings.get("principals")
        if not isinstance(raw_principals, dict) or not raw_principals:
            issues.append("'settings.principals' must be a non-empty mapping")
        else:
            principals = raw_principals
            for key, p in raw_principals.items():
                if not isinstance(p, dict):
                    issues.append(f"settings.principals.{key} must be a mapping")
                    continue
                if not p.get("name"):
                    issues.append(f"settings.principals.{key} is missing 'name'")
                if p.get("kind") not in ("group", "user"):
                    issues.append(f"settings.principals.{key}.kind must be 'group' or 'user'")
        # A section nested one level too deep (e.g. 'dev:' under 'settings:').
        for k in settings:
            if k != "principals":
                issues.append(f"unexpected key 'settings.{k}' — did you mean a top-level '{k}:'?")

    categories = raw.get("categories")
    if not isinstance(categories, dict) or not categories:
        issues.append("'categories' must be a non-empty mapping")
    else:
        for name, c in categories.items():
            if not isinstance(c, dict) or not c.get("user") or not c.get("group"):
                issues.append(f"categories.{name} must define 'user' and 'group'")

    rules = raw.get("rules")
    if not isinstance(rules, dict) or not rules:
        issues.append("'rules' must be a non-empty mapping")
    else:
        for name, r in rules.items():
            if not isinstance(r, dict) or "mode" not in r:
                issues.append(f"rules.{name} is missing 'mode'")
            elif "recursive" in r and not isinstance(r["recursive"], bool):
                issues.append(f"'rules.{name}.recursive' must be true or false")
        missing = _REQUIRED_RULES - set(rules)
        if missing:
            issues.append(f"missing required rule(s): {', '.join(sorted(missing))}")

    dev = raw.get("dev")
    if dev is not None and not isinstance(dev, dict):
        issues.append("'dev' must be a mapping")
    elif isinstance(dev, dict) and "principal" in dev:
        wanted = dev["principal"]
        names = {p.get("name") for p in principals.values() if isinstance(p, dict)}
        if wanted not in principals and wanted not in names:
            issues.append(f"dev.principal '{wanted}' matches no principal key or name")

    api = raw.get("api")
    if api is not None and not isinstance(api, dict):
        issues.append("'api' must be a mapping (e.g. api.manifest: /path/to/manifest.json)")

    for ext_key in ("images", "repos"):
        ext = raw.get(ext_key)
        if ext is None:
            continue
        if not isinstance(ext, dict):
            issues.append(f"'{ext_key}' must be a mapping (dir, owner, mode, acl)")
            continue
        if not ext.get("dir"):
            issues.append(f"'{ext_key}.dir' is required when '{ext_key}' is set")
        acl = ext.get("acl")
        if isinstance(acl, dict):
            for principal_name in acl:
                if principal_name not in principals:
                    issues.append(
                        f"{ext_key}.acl references unknown principal '{principal_name}'"
                    )
        elif acl is not None and not isinstance(acl, str):
            issues.append(f"'{ext_key}.acl' must be a mapping or null")
        if "recursive" in ext and not isinstance(ext["recursive"], bool):
            issues.append(f"'{ext_key}.recursive' must be true or false")

        df = ext.get("dockerfile")
        if df is not None and not isinstance(df, dict):
            issues.append(f"'{ext_key}.dockerfile' must be a mapping (mode, owner, acl)")
        elif isinstance(df, dict):
            df_acl = df.get("acl")
            if isinstance(df_acl, dict):
                for principal_name in df_acl:
                    if principal_name not in principals:
                        issues.append(
                            f"{ext_key}.dockerfile.acl references unknown principal "
                            f"'{principal_name}'"
                        )
            elif df_acl is not None and not isinstance(df_acl, str):
                issues.append(f"'{ext_key}.dockerfile.acl' must be a mapping or null")
            if "recursive" in df and not isinstance(df["recursive"], bool):
                issues.append(f"'{ext_key}.dockerfile.recursive' must be true or false")

    for k in raw:
        if k not in _KNOWN_TOP_LEVEL:
            issues.append(f"unknown top-level key '{k}'")

    return issues
