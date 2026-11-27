"""``clixz-inspect``: what the MCP gateway may read of the running containers.

systemd starts one per connection on ``/run/clixz-inspect.sock``
(``clixz-inspect.socket``, ``Accept=yes``): it reads one JSON request on
stdin, answers one JSON line and exits. It runs under a dynamic account whose
only privilege is the ``docker`` group — no capability, no writable path, no
network — and talks to dockerd in GET only (:mod:`clixz.docker_api`).

Only ``clixz-mcpd`` can connect (``root:svc_mcprun 0660``, not mounted in the
MCP container). As ``clixz-apply`` does, this process trusts it no more than
the internet: every field is checked again here. The requests are a closed
set::

    containers                      every container, summarised
    container        name           one container, filtered (no env values, no command)
    container-stats  [name]         CPU, memory, PIDs, I/O — of one, or of every running one
    container-logs   name [tail] [since]
                                    the last lines, masked; only for config.docker.logs
    docker-info                     dockerd's version, counts, storage, swarm state

Each request leaves one line in the unit's journal — the request, never what
was read.
"""

from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from . import runtime
from .config import Config, load_config
from .docker_api import DockerClient, DockerError, NotFound

MAX_REQUEST = 4 * 1024
STATS_WORKERS = 4


class RequestError(ValueError):
    """The request is malformed or not allowed. The message is caller-facing."""


def _log(message: str) -> None:
    print(f"[clixz-inspect] {message}", file=sys.stderr, flush=True)


def _container(req: dict, *, required: bool = True) -> str | None:
    value = req.get("name")
    if value is None and not required:
        return None
    if not isinstance(value, str) or not runtime.CONTAINER_RE.match(value):
        raise RequestError(f"invalid container name: {value!r}")
    return value


def _bounded(req: dict, key: str, default: int | None, maximum: int) -> int | None:
    value = req.get(key)
    if value is None:
        return default
    # bool is an int in Python; `true` is not a number of lines.
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise RequestError(f"'{key}' must be a whole number from 1 to {maximum}, got {value!r}")
    return value


def _containers(client: DockerClient, config: Config, req: dict) -> dict:
    items = [runtime.container_summary(c, config) for c in client.containers()]
    return {"ok": True, "containers": sorted(items, key=lambda c: c["name"])}


def _detail(client: DockerClient, config: Config, req: dict) -> dict:
    info = client.inspect(_container(req))  # type: ignore[arg-type]
    env = (info.get("Config") or {}).get("Env") or []
    return {"ok": True, "container": runtime.container_detail(info, config, runtime.Redactor(env))}


def _stats(client: DockerClient, config: Config, req: dict) -> dict:
    name = _container(req, required=False)
    if name is not None:
        return {"ok": True, "stats": [runtime.stats_view(name, client.stats(name))]}
    running = sorted(runtime.container_summary(c, config)["name"] for c in client.containers()
                     if c.get("State") == "running")

    def one(n: str) -> dict:
        try:
            return runtime.stats_view(n, client.stats(n))
        except DockerError as exc:  # the container stopped in between
            return {"name": n, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=STATS_WORKERS) as pool:
        return {"ok": True, "stats": list(pool.map(one, running))}


def _logs(client: DockerClient, config: Config, req: dict) -> dict:
    name = _container(req)
    tail = _bounded(req, "tail", runtime.DEFAULT_TAIL, runtime.MAX_TAIL)
    since = _bounded(req, "since", None, runtime.MAX_SINCE)
    info = client.inspect(name)  # type: ignore[arg-type]
    cfg = info.get("Config") or {}
    service = runtime.service_of(cfg.get("Labels"), config)
    if not runtime.logs_allowed(service, config):
        if service is None:
            raise RequestError("logs not allowed: this container belongs to no clixz service")
        raise RequestError(f"logs not allowed for {service}: only the operator opens them, by hand, "
                           f"in /etc/clixz/config.yaml (docker.logs: [{service}])")
    since_ts = int(time.time()) - since if since else None
    raw = client.logs(name, tail=tail, since=since_ts)  # type: ignore[arg-type]
    view = runtime.logs_view(raw, tty=bool(cfg.get("Tty")), redact=runtime.Redactor(cfg.get("Env")))
    return {"ok": True, "name": name, "service": service, "tail": tail, "since": since, **view}


def _info(client: DockerClient, config: Config, req: dict) -> dict:
    return {"ok": True, "docker": runtime.info_view(client.info())}


COMMANDS: dict[str, Callable[[DockerClient, Config, dict], dict]] = {
    "containers": _containers, "container": _detail, "container-stats": _stats,
    "container-logs": _logs, "docker-info": _info,
}


def handle(raw: bytes, config: Config, client: DockerClient | None = None) -> dict[str, Any]:
    if len(raw) > MAX_REQUEST:
        return {"ok": False, "error": f"request larger than {MAX_REQUEST // 1024} KiB"}
    try:
        req = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"ok": False, "error": f"malformed request: {exc}"}
    if not isinstance(req, dict):
        return {"ok": False, "error": "malformed request: an object is expected"}
    cmd = req.get("cmd")
    command = COMMANDS.get(cmd) if isinstance(cmd, str) else None
    if command is None:
        return {"ok": False, "error": f"command not allowed: {cmd!r} (known: {', '.join(COMMANDS)})"}
    client = client or DockerClient(str(config.docker.socket))
    try:
        answer = command(client, config, req)
    except RequestError as exc:
        _log(f"{cmd}: refused")
        return {"ok": False, "error": str(exc)}
    except NotFound:
        return {"ok": False, "error": f"no such container: {req.get('name')!r}"}
    except DockerError as exc:
        _log(f"{cmd}: {exc}")
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - the caller must always get an answer
        # The type only: a message could quote what dockerd sent.
        _log(f"{cmd}: unexpected {type(exc).__name__}")
        return {"ok": False, "error": f"{cmd} failed unexpectedly ({type(exc).__name__})"}
    _log(f"{cmd}" + (f" {req['name']}" if isinstance(req.get("name"), str) else ""))
    return answer


def main() -> None:
    raw = sys.stdin.buffer.readline(MAX_REQUEST + 1)
    try:
        config, _ = load_config()
    except (ValueError, OSError) as exc:
        response: dict[str, Any] = {"ok": False, "error": f"cannot load the config: {exc}"}
    else:
        response = handle(raw.rstrip(b"\n"), config)
    sys.stdout.write(json.dumps(response, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":  # pragma: no cover
    main()
