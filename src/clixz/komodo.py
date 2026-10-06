"""Create a new service's stack in Komodo, so the operator does not have to.

Komodo deploys every service from the tree: Periphery mounts ``/srv/docker``
at ``/services`` and each stack is "files on host" with its run directory
there. Creating that stack by hand after ``clixz new`` was the one step left
outside the tool. This module does it through Komodo Core's API — and only
that: no environment (the ``.env`` stays the operator's, in Komodo) and no
deployment. The stack appears, preconfigured, waiting to be completed and
deployed.

The API key belongs to a Komodo *service user* with no admin rights. Its file
is root's alone (0600): only ``clixz-apply`` and a root CLI read it, never
``clixz-mcpd`` or the MCP container.

Core is reached at the ``url`` in the credentials file, or else at its
container's address on the Docker network: its port is not published on the
host, and the address changes when the container is recreated, so it is looked
up on every call rather than written down.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from .config import Config


class KomodoError(RuntimeError):
    """Komodo could not be reached or refused the request. Caller-facing."""


@dataclass(frozen=True)
class Credentials:
    key: str
    secret: str
    url: str | None = None


def load_credentials(path: Path) -> Credentials:
    try:
        mode = path.stat().st_mode
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise KomodoError(
            f"no Komodo credentials at {path}: create an API key for a Komodo service user "
            "and write `key:` and `secret:` there (root, 0600)") from exc
    except (OSError, yaml.YAMLError) as exc:
        raise KomodoError(f"cannot read {path}: {exc}") from exc
    if mode & 0o077:
        raise KomodoError(f"{path} is readable by others — it holds an API secret: chmod 600 it")
    if not isinstance(raw, dict) or not raw.get("key") or not raw.get("secret"):
        raise KomodoError(f"{path} must define `key` and `secret`")
    url = str(raw["url"]).rstrip("/") if raw.get("url") else None
    return Credentials(key=str(raw["key"]), secret=str(raw["secret"]), url=url)


def container_ip(name: str) -> str | None:
    """The container's first address on a Docker network, or None."""
    if shutil.which("docker") is None:
        return None
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    addresses = out.split()
    return addresses[0] if addresses else None


class Client:
    """The two halves of Komodo's API clixz uses: ``/read`` and ``/write``."""

    def __init__(self, url: str, creds: Credentials,
                 opener: Callable[..., Any] = urllib.request.urlopen,
                 timeout: float = 15) -> None:
        self.url = url.rstrip("/")
        self.creds = creds
        self.opener = opener
        self.timeout = timeout

    def _call(self, half: str, request: str, params: dict) -> Any:
        http = urllib.request.Request(
            f"{self.url}/{half}/{request}",
            data=json.dumps(params).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "X-Api-Key": self.creds.key, "X-Api-Secret": self.creds.secret},
            method="POST",
        )
        try:
            with self.opener(http, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("error", "")
            except (ValueError, AttributeError, OSError):
                pass
            raise KomodoError(f"Komodo refused {request}: HTTP {exc.code}"
                              + (f" — {detail}" if detail else "")) from exc
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise KomodoError(f"Komodo Core unreachable at {self.url}: {reason}") from exc
        try:
            return json.loads(body.decode("utf-8")) if body else None
        except ValueError as exc:
            raise KomodoError(f"unreadable answer from Komodo to {request}: {exc}") from exc

    def read(self, request: str, params: dict) -> Any:
        return self._call("read", request, params)

    def write(self, request: str, params: dict) -> Any:
        return self._call("write", request, params)


def client_for(config: Config) -> Client:
    settings = config.komodo
    if settings.credentials is None:
        raise KomodoError("Komodo is not configured (no `komodo` section in the config)")
    creds = load_credentials(settings.credentials)
    url = creds.url
    if url is None:
        address = container_ip(settings.container)
        if address is None:
            raise KomodoError(f"cannot find the address of the {settings.container} container; "
                              "is Komodo Core running? Or set `url:` in the credentials file")
        url = f"http://{address}:{settings.port}"
    return Client(url, creds)


def _server_id(config: Config, client: Client) -> tuple[str, str]:
    """``(id, name)`` of the server the stack goes on."""
    servers = client.read("ListServers", {}) or []
    wanted = config.komodo.server
    if wanted:
        for server in servers:
            if wanted in (server.get("id"), server.get("name")):
                return str(server["id"]), str(server.get("name") or server["id"])
        known = ", ".join(str(s.get("name")) for s in servers) or "none"
        raise KomodoError(f"no Komodo server named {wanted!r} (known: {known})")
    if len(servers) == 1:
        return str(servers[0]["id"]), str(servers[0].get("name") or servers[0]["id"])
    raise KomodoError(f"Komodo has {len(servers)} servers: set `komodo.server` in the config")


def create_stack(config: Config, *, name: str, run_directory: str,
                 client: Client | None = None) -> str:
    """Create the stack unless one of that name exists; return what happened."""
    client = client or client_for(config)
    try:
        for stack in client.read("ListStacks", {}) or []:
            if stack.get("name") == name:
                return f"Komodo already has a stack named {name} — left as is"
        server_id, server_name = _server_id(config, client)
    except (KeyError, TypeError, AttributeError) as exc:
        raise KomodoError(f"unexpected answer from Komodo: {exc!r}") from exc
    client.write("CreateStack", {"name": name, "config": {
        "server_id": server_id, "files_on_host": True, "run_directory": run_directory,
    }})
    return (f"Komodo stack {name} created on {server_name} ({run_directory}) — "
            "fill in its environment and deploy it in Komodo")
