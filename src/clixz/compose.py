"""The compose.yaml: a starting template, and a lint that only ever warns.

v1 generated compose.yaml from a closed typed structure, on the reasoning that
generating is safer than validating. It is — but a structure that cannot express
a published port, a USB device or host networking does not make those needs go
away, it pushes them outside the system. The evidence was in the repository: an
``Exceptions`` dataclass with ten fields, then an ``elevated.yaml`` allowlist,
both added to reopen a model that had been closed on purpose.

v2 inverts it. ``clixz new`` writes a complete, hardened compose that is yours to
edit, and ``clixz check`` reads it back and *warns*. A warning gets read and
decided; an inexpressible need gets worked around outside the tool.
"""

from __future__ import annotations

import grp
import pwd
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import Config
from .rules import LintRules

DEFAULT_NETWORK = "boxyz_network"

_PORT_RE = re.compile(
    r"^(?:(?P<ip>[0-9.]+|\[[0-9a-fA-F:]+\]):)?(?P<host>\d+):(?P<container>\d+)(?:/\w+)?$"
)


@dataclass(frozen=True)
class LintFinding:
    service: str        # the compose service key the finding is about
    level: str          # "error" | "warn" | "info"
    message: str
    rule: str = ""      # the id lint.yaml and ignore.yaml refer to


# ─── template ────────────────────────────────────────────────────────────────

def category_uid_gid(config: Config, category: str) -> str | None:
    """``"uid:gid"`` for a category's account, or None if it does not resolve."""
    cat = config.category(category)
    try:
        return f"{pwd.getpwnam(cat.user).pw_uid}:{grp.getgrnam(cat.group).gr_gid}"
    except KeyError:
        return None


def template(config: Config, category: str, service: str) -> str:
    """A complete compose.yaml to start from — hardened, and meant to be edited.

    Quoting ``user:`` is not cosmetic: an unquoted ``988:982`` is a YAML 1.1
    sexagesimal integer, and the container would silently run under the wrong
    uid.
    """
    svc_dir = config.root_dir / category / service
    user = category_uid_gid(config, category)
    user_line = (
        f'    user: "{user}"\n'
        if user
        else f"    # user: \"<uid>:<gid>\"   # {config.category(category).owner} "
             "does not resolve on this host\n"
    )
    return f"""\
# {category}/{service} — edit freely. `clixz check` lints this file and warns;
# it never rewrites it. See /srv/docs/conventions/ for the house rules.
services:
  {service}:
    image: TODO:pin-a-version
    container_name: {service}
    restart: unless-stopped
{user_line}\
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    networks: [{DEFAULT_NETWORK}]
    env_file: [.env]
    volumes:
      # Absolute, not ./ — Komodo deploys the stack and its working directory is
      # not guaranteed to be this one. Every existing service does the same.
      - {svc_dir}/config:/config:ro
      - {svc_dir}/data:/data
    # expose: ["8080"]        # reachable from the docker network only
    # ports: ["127.0.0.1:8080:8080"]   # bind to localhost unless the LAN needs it
    healthcheck:
      test: ["CMD", "true"]   # TODO: a real check
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"

networks:
  {DEFAULT_NETWORK}:
    external: true
"""


# ─── lint ────────────────────────────────────────────────────────────────────

def load_compose(path: Path) -> dict[str, Any] | None:
    """Parse a compose file, or None when it is absent, empty or unreadable."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return raw if isinstance(raw, dict) else None


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _caps_dropped(body: dict) -> bool:
    return any(str(c).upper() == "ALL" for c in _as_list(body.get("cap_drop")))


def _no_new_privileges(body: dict) -> bool:
    return any(
        str(opt).replace(" ", "").lower().startswith("no-new-privileges:true")
        for opt in _as_list(body.get("security_opt"))
    )


class _Findings:
    """Collects findings for one service at the level lint.yaml gives each rule."""

    def __init__(self, service: str, rules: LintRules) -> None:
        self.service = service
        self.rules = rules
        self.items: list[LintFinding] = []

    def add(self, rule: str, message: str) -> None:
        level = self.rules.level(rule)
        if level != "off":
            self.items.append(LintFinding(self.service, level, message, rule))


def _lint_image(out: _Findings, body: dict) -> None:
    image = str(body.get("image", "")).strip()
    if not image:
        if not body.get("build"):
            out.add("no-image", "no image and no build context")
        return
    tag = image.rpartition("/")[2]
    if "@sha256:" in image:
        return
    if ":" not in tag:
        out.add("image-untagged", f"image {image} has no tag — pin a version")
    elif tag.endswith(":latest"):
        out.add("image-latest",
                f"image {image} is pinned to :latest — a redeploy can change the code "
                "under you without a diff")


def _lint_volumes(out: _Findings, body: dict, svc_dir: Path | None) -> None:
    for entry in _as_list(body.get("volumes")):
        if isinstance(entry, dict):
            source = str(entry.get("source", ""))
            read_only = bool(entry.get("read_only"))
        else:
            parts = str(entry).split(":")
            source = parts[0] if parts else ""
            read_only = len(parts) > 2 and "ro" in parts[2].split(",")
        if not source.startswith(("/", "./", "../")):
            continue  # a named volume
        # "/" rstrips to "", which would make the `== "/"` check below miss the
        # single most dangerous mount there is.
        resolved = source.rstrip("/") or "/"

        def _under(prefixes: tuple[str, ...], resolved: str = resolved) -> bool:
            return any(resolved == p or resolved.startswith(p + "/") for p in prefixes)

        if _under(out.rules.critical):
            out.add("mount-critical",
                    f"mounts {source} — this is equivalent to handing over host root")
        elif _under(out.rules.critical_if_writable):
            if read_only:
                out.add("mount-config-ro", f"mounts {source} read-only")
            else:
                out.add("mount-config-rw",
                        f"mounts {source} read-write — the container can rewrite the "
                        "rules that constrain it")
        elif resolved == "/":
            out.add("mount-root", "mounts / — the container can read every secret")
        elif source.startswith("/") and svc_dir is not None:
            inside = Path(resolved) == svc_dir or svc_dir in Path(resolved).parents
            if not inside:
                out.add("mount-host",
                        f"mounts the host path {source}" + ("" if read_only else " read-write"))


def _lint_ports(out: _Findings, body: dict) -> None:
    for entry in _as_list(body.get("ports")):
        if isinstance(entry, dict):
            published, host_ip = str(entry.get("published", "")), str(entry.get("host_ip", ""))
            if published and host_ip in ("", "0.0.0.0", "::"):
                out.add("port-all-interfaces",
                        f"publishes {published} on every interface — prefix 127.0.0.1: "
                        "unless the LAN genuinely needs it")
            continue
        match = _PORT_RE.match(str(entry))
        if match and match.group("ip") in (None, "0.0.0.0", "[::]"):
            out.add("port-all-interfaces",
                    f"publishes {entry} on every interface — prefix 127.0.0.1: unless "
                    "the LAN genuinely needs it")


def lint_service(name: str, body: dict, svc_dir: Path | None = None,
                 rules: LintRules | None = None) -> list[LintFinding]:
    """Lint one compose service body. Never raises; returns findings."""
    out = _Findings(name, rules or LintRules())
    if not isinstance(body, dict):
        out.add("compose-invalid", "service body is not a mapping")
        return out.items

    if body.get("privileged"):
        out.add("privileged",
                "privileged: true — a compromise of this container is a compromise "
                "of the host")
    if str(body.get("network_mode", "")).startswith("host"):
        out.add("network-host", "network_mode: host — the container shares the host's stack")
    if body.get("pid") == "host":
        out.add("pid-host", "pid: host")

    _lint_image(out, body)
    _lint_volumes(out, body, svc_dir)
    _lint_ports(out, body)

    if not _caps_dropped(body):
        out.add("no-cap-drop", "no cap_drop: [ALL]")
    if not _no_new_privileges(body):
        out.add("no-new-privileges", "no security_opt: [no-new-privileges:true]")
    if not body.get("user") and not body.get("privileged"):
        out.add("no-user", "no user: — the container runs as whatever the image says, "
                "often root")
    if not body.get("restart"):
        out.add("no-restart", "no restart policy")

    logging = body.get("logging")
    options = logging.get("options") if isinstance(logging, dict) else None
    if not isinstance(options, dict) or not options.get("max-size"):
        out.add("no-log-rotation", "no logging max-size — this log can fill the disk")
    if not body.get("healthcheck"):
        out.add("no-healthcheck", "no healthcheck")

    for key in ("cap_add", "devices", "sysctls"):
        if body.get(key):
            values = ", ".join(str(v) for v in _as_list(body[key])[:4])
            out.add("extra-privileges", f"{key}: {values}")

    return out.items


def lint_compose(path: Path, svc_dir: Path | None = None,
                 rules: LintRules | None = None) -> list[LintFinding]:
    """Lint every service in a compose file."""
    rules = rules or LintRules()
    whole = _Findings("", rules)
    doc = load_compose(path)
    if doc is None:
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            whole.add("compose-empty", "compose.yaml is empty")
        else:
            whole.add("compose-invalid", "compose.yaml is not readable YAML")
        return whole.items

    services = doc.get("services")
    if not isinstance(services, dict) or not services:
        whole.add("compose-invalid", "compose.yaml declares no services")
        return whole.items

    out: list[LintFinding] = []
    for name, body in services.items():
        out += lint_service(str(name), body, svc_dir, rules)
    return out


def summarize(path: Path) -> tuple[str, list[str], list[str]]:
    """``(image, published_ports, container_names)`` for the listing commands."""
    doc = load_compose(path)
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return "", [], []
    images, ports, names = [], [], []
    for key, body in services.items():
        if not isinstance(body, dict):
            continue
        if body.get("image"):
            images.append(str(body["image"]))
        names.append(str(body.get("container_name") or key))
        for entry in _as_list(body.get("ports")):
            ports.append(str(entry) if not isinstance(entry, dict)
                         else str(entry.get("published", "")))
    return (images[0] if images else ""), ports, names
