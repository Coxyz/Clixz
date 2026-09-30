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

DEFAULT_NETWORK = "boxyz_network"

# Host paths that hand over the machine however they are mounted. Read-only
# changes nothing here: :ro on a socket still lets you talk to the daemon, and
# read access to /etc/shadow or /root/.ssh is the whole prize.
ALWAYS_CRITICAL = (
    "/var/run/docker.sock", "/run/docker.sock", "/var/lib/docker",
    "/etc/shadow", "/root", "/boot",
)

# Paths that hand over the machine only when writable. Read-only, they are
# ordinary configuration a container may legitimately need — the MCP container
# reads /etc/clixz/config.yaml to answer questions about it, and flagging that
# as host-root would be a false positive that teaches the reader to ignore the
# linter.
CRITICAL_IF_WRITABLE = ("/etc/clixz", "/etc/systemd", "/etc/sudoers", "/etc/sudoers.d")

_PORT_RE = re.compile(
    r"^(?:(?P<ip>[0-9.]+|\[[0-9a-fA-F:]+\]):)?(?P<host>\d+):(?P<container>\d+)(?:/\w+)?$"
)


@dataclass(frozen=True)
class LintFinding:
    service: str        # the compose service key the finding is about
    level: str          # "error" | "warn" | "info"
    message: str


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


def _lint_image(name: str, body: dict) -> list[LintFinding]:
    image = str(body.get("image", "")).strip()
    if not image:
        if not body.get("build"):
            return [LintFinding(name, "error", "no image and no build context")]
        return []
    tag = image.rpartition("/")[2]
    if "@sha256:" in image:
        return []
    if ":" not in tag:
        return [LintFinding(name, "warn", f"image {image} has no tag — pin a version")]
    if tag.endswith(":latest"):
        return [LintFinding(
            name, "warn",
            f"image {image} is pinned to :latest — a redeploy can change the code "
            "under you without a diff",
        )]
    return []


def _lint_volumes(name: str, body: dict, svc_dir: Path | None) -> list[LintFinding]:
    out: list[LintFinding] = []
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

        if _under(ALWAYS_CRITICAL):
            out.append(LintFinding(
                name, "error",
                f"mounts {source} — this is equivalent to handing over host root",
            ))
        elif _under(CRITICAL_IF_WRITABLE):
            if read_only:
                out.append(LintFinding(
                    name, "info", f"mounts {source} read-only",
                ))
            else:
                out.append(LintFinding(
                    name, "error",
                    f"mounts {source} read-write — the container can rewrite the "
                    "rules that constrain it",
                ))
        else:
            if resolved == "/":
                out.append(LintFinding(
                    name, "error", "mounts / — the container can read every secret",
                ))
            elif source.startswith("/") and svc_dir is not None:
                inside = Path(resolved) == svc_dir or svc_dir in Path(resolved).parents
                if not inside:
                    out.append(LintFinding(
                        name, "warn",
                        f"mounts the host path {source}"
                        + ("" if read_only else " read-write"),
                    ))
    return out


def _lint_ports(name: str, body: dict) -> list[LintFinding]:
    out: list[LintFinding] = []
    for entry in _as_list(body.get("ports")):
        if isinstance(entry, dict):
            published, host_ip = str(entry.get("published", "")), str(entry.get("host_ip", ""))
            if published and host_ip in ("", "0.0.0.0", "::"):
                out.append(LintFinding(
                    name, "warn",
                    f"publishes {published} on every interface — prefix 127.0.0.1: "
                    "unless the LAN genuinely needs it",
                ))
            continue
        match = _PORT_RE.match(str(entry))
        if match and match.group("ip") in (None, "0.0.0.0", "[::]"):
            out.append(LintFinding(
                name, "warn",
                f"publishes {entry} on every interface — prefix 127.0.0.1: unless "
                "the LAN genuinely needs it",
            ))
    return out


def lint_service(name: str, body: dict, svc_dir: Path | None = None) -> list[LintFinding]:
    """Lint one compose service body. Never raises; returns findings."""
    out: list[LintFinding] = []
    if not isinstance(body, dict):
        return [LintFinding(name, "error", "service body is not a mapping")]

    if body.get("privileged"):
        out.append(LintFinding(
            name, "error",
            "privileged: true — a compromise of this container is a compromise "
            "of the host",
        ))
    if str(body.get("network_mode", "")).startswith("host"):
        out.append(LintFinding(
            name, "error", "network_mode: host — the container shares the host's stack",
        ))
    if body.get("pid") == "host":
        out.append(LintFinding(name, "error", "pid: host"))

    out += _lint_image(name, body)
    out += _lint_volumes(name, body, svc_dir)
    out += _lint_ports(name, body)

    if not _caps_dropped(body):
        out.append(LintFinding(name, "warn", "no cap_drop: [ALL]"))
    if not _no_new_privileges(body):
        out.append(LintFinding(name, "warn", "no security_opt: [no-new-privileges:true]"))
    if not body.get("user") and not body.get("privileged"):
        out.append(LintFinding(
            name, "info", "no user: — the container runs as whatever the image says, "
            "often root",
        ))
    if not body.get("restart"):
        out.append(LintFinding(name, "warn", "no restart policy"))

    logging = body.get("logging")
    options = logging.get("options") if isinstance(logging, dict) else None
    if not isinstance(options, dict) or not options.get("max-size"):
        out.append(LintFinding(
            name, "warn", "no logging max-size — this log can fill the disk",
        ))
    if not body.get("healthcheck"):
        out.append(LintFinding(name, "info", "no healthcheck"))

    for key in ("cap_add", "devices", "sysctls"):
        if body.get(key):
            values = ", ".join(str(v) for v in _as_list(body[key])[:4])
            out.append(LintFinding(name, "info", f"{key}: {values}"))

    return out


def lint_compose(path: Path, svc_dir: Path | None = None) -> list[LintFinding]:
    """Lint every service in a compose file."""
    doc = load_compose(path)
    if doc is None:
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            return [LintFinding("", "warn", "compose.yaml is empty")]
        return [LintFinding("", "error", "compose.yaml is not readable YAML")]

    services = doc.get("services")
    if not isinstance(services, dict) or not services:
        return [LintFinding("", "error", "compose.yaml declares no services")]

    out: list[LintFinding] = []
    for name, body in services.items():
        out += lint_service(str(name), body, svc_dir)
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
