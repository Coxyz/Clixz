"""A read-only client for the Docker Engine API, over its Unix socket.

Only ``GET``: the class has no other method, so nothing built on it can start,
stop, exec or create anything. Holding the socket is root on the host, which is
why this client is small, stdlib-only (``http.client``), and used by a process
that lives for one request (``clixz-inspect``).
"""

from __future__ import annotations

import http.client
import json
import socket
from typing import Any
from urllib.parse import quote, urlencode

# dockerd's answers are small, except logs, which the caller bounds by `tail`.
MAX_BODY = 8 * 1024 * 1024


class DockerError(RuntimeError):
    """dockerd refused or could not be reached. The message is caller-facing."""


class NotFound(DockerError):
    pass


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("docker", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


class DockerClient:
    def __init__(self, socket_path: str, timeout: float = 30.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def _get(self, path: str, params: dict[str, Any] | None = None) -> bytes:
        url = path + ("?" + urlencode(params) if params else "")
        conn = _UnixConnection(self.socket_path, self.timeout)
        try:
            conn.request("GET", url)
            resp = conn.getresponse()
            body = resp.read(MAX_BODY + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(f"dockerd unreachable: {exc}") from exc
        finally:
            conn.close()
        if len(body) > MAX_BODY:
            raise DockerError(f"dockerd answered more than {MAX_BODY // (1024 * 1024)} MiB")
        if resp.status == 404:
            raise NotFound(_message(body) or "not found")
        if resp.status >= 400:
            raise DockerError(f"dockerd: {resp.status} {_message(body)}".strip())
        return body

    def _json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            return json.loads(self._get(path, params))
        except ValueError as exc:
            raise DockerError(f"unreadable answer from dockerd: {exc}") from exc

    # ── the closed set of reads ─────────────────────────────────────────────

    def containers(self) -> list[dict]:
        return self._json("/containers/json", {"all": "1"})

    def inspect(self, name: str) -> dict:
        return self._json(f"/containers/{_ref(name)}/json")

    def stats(self, name: str) -> dict:
        # stream=false: dockerd samples twice, so the answer carries precpu_stats.
        return self._json(f"/containers/{_ref(name)}/stats", {"stream": "false"})

    def logs(self, name: str, *, tail: int, since: int | None = None) -> bytes:
        params: dict[str, Any] = {"stdout": "1", "stderr": "1", "timestamps": "1",
                                  "tail": str(int(tail))}
        if since:
            params["since"] = str(int(since))
        return self._get(f"/containers/{_ref(name)}/logs", params)

    def info(self) -> dict:
        return self._json("/info")


def _ref(name: str) -> str:
    # The caller validated the name; quoting keeps the path closed regardless.
    return quote(name, safe="")


def _message(body: bytes) -> str:
    try:
        return str(json.loads(body).get("message", ""))[:300]
    except (ValueError, AttributeError):
        return ""


def demux(raw: bytes, tty: bool) -> list[tuple[str, str]]:
    """``[(stream, text)]`` from a logs answer.

    Without a TTY dockerd multiplexes stdout and stderr in frames: one byte of
    stream id, three of padding, four of big-endian length. With a TTY the
    output is raw and all of it is stdout.
    """
    if tty:
        return [("out", raw.decode("utf-8", "replace"))]
    out: list[tuple[str, str]] = []
    i = 0
    while i + 8 <= len(raw):
        stream, size = raw[i], int.from_bytes(raw[i + 4:i + 8], "big")
        chunk = raw[i + 8:i + 8 + size]
        out.append(("err" if stream == 2 else "out", chunk.decode("utf-8", "replace")))
        i += 8 + size
    return out
