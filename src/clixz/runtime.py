"""What the MCP may see of the running containers: filtered views of dockerd's answers.

Every function here turns a raw Engine API answer into a dict that is safe to
hand to a model behind a public endpoint. The rule is an allowlist: a field is
returned because it is named here, never because dockerd sent it. What never
leaves: environment *values*, the command line (``Cmd``, ``Entrypoint``,
``Args``), label values outside ``com.docker.compose.*``, logging options that
may hold a token. Logs leave only for the services the operator listed in
``docker.logs``, and are masked on the way out — best effort, which is why the
list exists.
"""

from __future__ import annotations

import re
from typing import Any

from .config import Config
from .docker_api import demux

CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DEFAULT_TAIL = 200
MAX_TAIL = 1000
MAX_SINCE = 7 * 24 * 3600
MAX_LOG_BYTES = 256 * 1024
MAX_LINE = 2000
MAX_HEALTH_OUTPUT = 500

_COMPOSE_LABELS = ("com.docker.compose.project", "com.docker.compose.service",
                   "com.docker.compose.project.working_dir", "com.docker.compose.container-number")
_LOG_OPTIONS = {"max-size", "max-file", "compress", "mode", "max-buffer-size"}
_SENSITIVE_SOURCES = {"/", "/proc", "/sys", "/dev", "/etc", "/root", "/home", "/boot",
                      "/run", "/var/run", "/var/lib/docker"}
_SENSITIVE_PREFIXES = ("/proc/", "/sys/", "/etc/", "/root/", "/boot/", "/var/lib/docker/")


# ─── which clixz service a container belongs to ──────────────────────────────

def service_of(labels: dict | None, config: Config) -> str | None:
    """``category/service`` from compose's working directory, or None.

    Komodo runs compose from the tree as Periphery mounts it (``run_root``,
    ``/services``); a compose started by hand on the host runs from
    ``root_dir``. Anything else is not a clixz service.
    """
    wd = (labels or {}).get("com.docker.compose.project.working_dir")
    if not isinstance(wd, str):
        return None
    for base in (config.komodo.run_root, str(config.root_dir)):
        base = base.rstrip("/")
        if wd.startswith(base + "/"):
            parts = wd[len(base) + 1:].strip("/").split("/")
            if len(parts) == 2 and parts[0] in config.categories and all(parts):
                return "/".join(parts)
    return None


def logs_allowed(service: str | None, config: Config) -> bool:
    return service is not None and service in config.docker.logs


# ─── views ───────────────────────────────────────────────────────────────────

def _name(raw: Any) -> str:
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    return str(raw or "").lstrip("/")


def _health_from_status(status: str) -> str | None:
    for marker, value in (("(healthy)", "healthy"), ("(unhealthy)", "unhealthy"),
                          ("(health: starting)", "starting")):
        if marker in status:
            return value
    return None


def _ports_list(ports: list | None) -> list[str]:
    out = []
    for p in ports or []:
        private = f"{p.get('PrivatePort')}/{p.get('Type', 'tcp')}"
        if p.get("PublicPort"):
            out.append(f"{p.get('IP', '')}:{p['PublicPort']}->{private}")
        else:
            out.append(private)
    return sorted(set(out))


def container_summary(c: dict, config: Config) -> dict:
    labels = c.get("Labels") or {}
    service = service_of(labels, config)
    status = str(c.get("Status") or "")
    return {
        "name": _name(c.get("Names")),
        "id": str(c.get("Id", ""))[:12],
        "image": c.get("Image"),
        "state": c.get("State"),
        "status": status,
        "health": _health_from_status(status),
        "ports": _ports_list(c.get("Ports")),
        "compose_project": labels.get("com.docker.compose.project"),
        "compose_service": labels.get("com.docker.compose.service"),
        "service": service,
        "logs_allowed": logs_allowed(service, config),
    }


def sensitive_source(source: str) -> bool:
    if source.endswith("docker.sock"):
        return True
    source = source.rstrip("/") or "/"
    return source in _SENSITIVE_SOURCES or source.startswith(_SENSITIVE_PREFIXES)


def container_detail(info: dict, config: Config, redact: Redactor | None = None) -> dict:
    """The audit view of one container. ``redact`` is given only when logs are allowed."""
    cfg = info.get("Config") or {}
    host = info.get("HostConfig") or {}
    state = info.get("State") or {}
    labels = cfg.get("Labels") or {}
    service = service_of(labels, config)
    allowed = logs_allowed(service, config)
    health = state.get("Health") or {}
    checks = []
    for entry in (health.get("Log") or [])[-3:]:
        check = {"start": entry.get("Start"), "end": entry.get("End"),
                 "exit_code": entry.get("ExitCode")}
        if allowed and redact is not None:
            check["output"] = redact(clean(str(entry.get("Output") or "")))[:MAX_HEALTH_OUTPUT]
        checks.append(check)
    log_config = host.get("LogConfig") or {}
    networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
    out = {
        "name": _name(info.get("Name")),
        "id": str(info.get("Id", ""))[:12],
        "image": cfg.get("Image"),
        "image_id": str(info.get("Image", ""))[:19],
        "created": info.get("Created"),
        "service": service,
        "logs_allowed": allowed,
        "state": {
            "status": state.get("Status"),
            "running": state.get("Running"),
            "restarting": state.get("Restarting"),
            "oom_killed": state.get("OOMKilled"),
            "exit_code": state.get("ExitCode"),
            # dockerd's own error (a failed start, a missing device), not the app's output.
            # It can quote the command line, so it is masked like an output.
            "error": (redact or Redactor())(clean(str(state.get("Error") or "")))[:MAX_HEALTH_OUTPUT]
            or None,
            "started_at": state.get("StartedAt"),
            "finished_at": state.get("FinishedAt"),
            "restart_count": info.get("RestartCount"),
            "health": ({"status": health.get("Status"), "failing_streak": health.get("FailingStreak"),
                        "last_checks": checks} if health else None),
        },
        "user": cfg.get("User") or None,
        # NAMES only: a value may be a secret, and the model has no use for one.
        "environment_keys": sorted({str(e).split("=", 1)[0] for e in cfg.get("Env") or []}),
        "labels": {k: labels[k] for k in _COMPOSE_LABELS if k in labels},
        "other_label_keys": sorted(k for k in labels if not k.startswith("com.docker.compose.")),
        # Compose has substituted ${VAR} here, and a value passed only on a
        # command line is not in the environment the masking knows: like Cmd,
        # the test leaves only where the logs may, and masked.
        "healthcheck_test": ([redact(clean(str(part)))
                              for part in (cfg.get("Healthcheck") or {}).get("Test") or []] or None)
        if allowed and redact is not None else None,
        "security": {
            "privileged": host.get("Privileged"),
            "cap_add": host.get("CapAdd") or [],
            "cap_drop": host.get("CapDrop") or [],
            "security_opt": host.get("SecurityOpt") or [],
            "read_only_rootfs": host.get("ReadonlyRootfs"),
            "group_add": host.get("GroupAdd") or [],
            "devices": [f"{d.get('PathOnHost')}:{d.get('PathInContainer')}"
                        for d in host.get("Devices") or []],
            "network_mode": host.get("NetworkMode"),
            "pid_mode": host.get("PidMode") or None,
            "ipc_mode": host.get("IpcMode") or None,
            "userns_mode": host.get("UsernsMode") or None,
            "sysctl_keys": sorted(host.get("Sysctls") or {}),
        },
        "limits": {
            "memory": host.get("Memory") or None,
            "memory_swap": host.get("MemorySwap") or None,
            "memory_reservation": host.get("MemoryReservation") or None,
            "nano_cpus": host.get("NanoCpus") or None,
            "pids_limit": host.get("PidsLimit") or None,
        },
        "restart_policy": (host.get("RestartPolicy") or {}).get("Name"),
        "logging": {
            "driver": log_config.get("Type"),
            "options": {k: (v if k in _LOG_OPTIONS else "[masqué]")
                        for k, v in (log_config.get("Config") or {}).items()},
        },
        "mounts": [
            {"type": m.get("Type"), "source": m.get("Source"), "destination": m.get("Destination"),
             "rw": m.get("RW"), "sensitive": sensitive_source(str(m.get("Source") or ""))}
            for m in info.get("Mounts") or []
        ],
        "ports": sorted(
            f"{b.get('HostIp', '')}:{b.get('HostPort')}->{port}"
            for port, binds in ((info.get("NetworkSettings") or {}).get("Ports") or {}).items()
            for b in binds or []
        ),
        "networks": {name: (n or {}).get("IPAddress") or None for name, n in networks.items()},
    }
    return out


def stats_view(name: str, s: dict) -> dict:
    cpu, pre = s.get("cpu_stats") or {}, s.get("precpu_stats") or {}
    cpu_delta = ((cpu.get("cpu_usage") or {}).get("total_usage", 0)
                 - (pre.get("cpu_usage") or {}).get("total_usage", 0))
    sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    online = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
    cpu_pct = round(cpu_delta / sys_delta * online * 100, 2) if sys_delta > 0 and cpu_delta >= 0 else None
    mem = s.get("memory_stats") or {}
    usage, limit = mem.get("usage"), mem.get("limit")
    detail = mem.get("stats") or {}
    # As `docker stats` does: the page cache the kernel can drop is not "used".
    cache = detail.get("inactive_file", detail.get("total_inactive_file", 0))
    used = usage - cache if isinstance(usage, int) else None
    io = (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
    nets = list((s.get("networks") or {}).values())
    return {
        "name": name,
        "cpu_percent": cpu_pct,
        "memory_used": used,
        "memory_limit": limit,
        "memory_percent": round(used / limit * 100, 2) if used is not None and limit else None,
        "pids": (s.get("pids_stats") or {}).get("current"),
        "net_rx_bytes": sum(n.get("rx_bytes", 0) for n in nets),
        "net_tx_bytes": sum(n.get("tx_bytes", 0) for n in nets),
        "block_read_bytes": sum(e.get("value", 0) for e in io if str(e.get("op")).lower() == "read"),
        "block_write_bytes": sum(e.get("value", 0) for e in io if str(e.get("op")).lower() == "write"),
    }


_INFO_KEYS = ("ServerVersion", "Containers", "ContainersRunning", "ContainersPaused",
              "ContainersStopped", "Images", "Driver", "CgroupDriver", "CgroupVersion",
              "KernelVersion", "OperatingSystem", "Architecture", "NCPU", "MemTotal")


def info_view(info: dict) -> dict:
    out = {k: info.get(k) for k in _INFO_KEYS}
    # Swarm is still active on Boxyz with no service (todo #15): worth seeing.
    out["Swarm"] = (info.get("Swarm") or {}).get("LocalNodeState")
    return out


# ─── logs: cleaning and masking ──────────────────────────────────────────────

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SECRET_NAME = re.compile(
    r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
    r"|client[_-]?secret|session|cookie|credential|auth|signature|salt|dsn|database_url|key",
    re.IGNORECASE)
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
                re.DOTALL), "[masqué:clé privée]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(?:(bearer|basic|token|digest)\s+)?[^\s,;\"']+"),
     r"\1\2 [masqué]"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+):[^/\s@]+@"), r"\1:[masqué]@"),
    # Anchored at the start of a word: unanchored, a long word costs n² (see _token).
    (re.compile(
        r"(?i)(?<![\w.-])([\w.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
        r"|private[_-]?key|client[_-]?secret|session[_-]?id|cookie|credential|signature)[\w.-]*"
        r"[\"']?\s*[:=]\s*[\"']?)(?!\[masqué)([^\s\"'&,;}]+)"), r"\1[masqué]"),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "[masqué:jwt]"),
    # Opaque tokens; pure hex is left alone, it is ids and digests.
]
# Opaque tokens: 40+ characters of a word, with a digit and a letter beyond
# hex — pure hex is ids and digests. Without "/": a long path is not a token.
# The test is a function, not lookaheads, which rescan the word at each
# position: n² on one long line, and a service controls its own lines.
_WORD = re.compile(r"(?<![\w-])[\w-]{40,}={0,2}(?![\w-])")
_NON_HEX = re.compile(r"[g-zG-Z]")


def _token(match: re.Match[str]) -> str:
    word = match.group(0)
    if any(ch.isdigit() for ch in word) and _NON_HEX.search(word):
        return "[masqué:jeton]"
    return word


class Redactor:
    """Masks a container's environment values, then known secret shapes, in text."""

    def __init__(self, env: list[str] | None = None) -> None:
        values: dict[str, str] = {}
        for item in env or []:
            key, sep, value = str(item).partition("=")
            if not sep or not value:
                continue
            if len(value) >= 8 or (len(value) >= 3 and _SECRET_NAME.search(key)):
                values.setdefault(value, key)
        # Longest first, so a value that contains another is masked whole.
        self._values = sorted(values.items(), key=lambda kv: -len(kv[0]))

    def __call__(self, text: str) -> str:
        for value, key in self._values:
            if value in text:
                text = text.replace(value, f"[masqué:{key}]")
        for pattern, repl in _PATTERNS:
            text = pattern.sub(repl, text)
        return _WORD.sub(_token, text)


def clean(text: str) -> str:
    """No terminal escapes nor control characters (tabs and newlines stay)."""
    return _CONTROL.sub("", _ANSI.sub("", text))


def logs_view(raw: bytes, *, tty: bool, redact: Redactor) -> dict:
    """Lines of a logs answer, cleaned, masked and bounded (the most recent kept)."""
    text = "".join(f"{chunk}" for _, chunk in demux(raw, tty))
    # Cleaned first: an escape between a key and its "=" would hide the pair
    # from the masking. Masked before splitting: a PEM block spans lines.
    lines = [line[:MAX_LINE] for line in redact(clean(text)).splitlines()]
    kept: list[str] = []
    size = 0
    for line in reversed(lines):
        size += len(line.encode("utf-8")) + 1
        if size > MAX_LOG_BYTES:
            break
        kept.append(line)
    kept.reverse()
    return {"lines": kept, "count": len(kept), "truncated": len(kept) < len(lines)}
