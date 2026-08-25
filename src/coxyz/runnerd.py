"""Unprivileged gateway between the MCP container and the CLI.

The container is deliberately unable to act on the host: ``cap_drop: ALL``,
read-only rootfs, ``/srv/docker`` mounted ``:ro``, no CLI binary. This daemon is
the only bridge, and it is narrow on purpose:

- it runs **unprivileged** as ``svc_mcprun`` — an account with no supplementary
  privilege, notably neither ``sudo`` nor ``docker``. Read-only commands need
  nothing more;
- read-only commands come from a **closed allowlist** and every argument is
  regex-checked; nothing reaches a shell;
- mutating commands are **not executed here at all**. They are relayed, as
  typed JSON, to :mod:`coxyz.admind`, which holds the narrow set of capabilities
  they require. This daemon cannot chown, cannot setfacl, cannot delete.

The split matters: an escape in this process yields an account that can read the
service tree and ask ``admind`` for a *plan*. It yields no write, and no
``--force``.

Protocol — one JSON request per connection, newline-terminated::

    {"cmd": "check", "service": "bitwarden"}
    {"cmd": "plan", "action": "update", "service": "x", "patch": {...}}
    {"cmd": "apply", "plan_id": "...", "hash": "..."}
"""

from __future__ import annotations

import json
import os
import re
import socket
import socketserver
import subprocess
import sys

COXYZ_BIN = os.environ.get("COXYZ_BIN", "/opt/pipx/venvs/coxyz-cli/bin/coxyz")
SOCKET_PATH = os.environ.get("COXYZ_RUNNER_SOCKET", "/run/coxyz-runner/coxyz-runner.sock")
ADMIN_SOCKET = os.environ.get("COXYZ_ADMIN_SOCKET", "/run/coxyz-admin/coxyz-admin.sock")
TIMEOUT = int(os.environ.get("COXYZ_RUNNER_TIMEOUT", "60"))
MAX_OUTPUT = 256 * 1024
MAX_REQUEST = 256 * 1024

_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$")
_CATEGORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Relayed verbatim to admind, which does its own validation. Listing them here
# keeps this daemon's surface explicit rather than "anything admind accepts".
RELAYED = ("plan", "apply")


def _build_argv(req: dict) -> list[str]:
    """Translate a validated request into argv, or raise ValueError.

    All of the safety lives here: the subcommand comes from a closed set and the
    only variable arguments are a service or category name, both regex-checked.
    No free-form argument is ever accepted.
    """
    cmd = req.get("cmd")

    if cmd == "check":
        argv = [COXYZ_BIN, "check"]
        service = req.get("service")
        if service:
            # Require a real string: str(42) would satisfy the regex, so a
            # non-string would be silently coerced instead of refused.
            if not isinstance(service, str) or not _SERVICE_RE.match(service):
                raise ValueError(f"invalid service name: {service!r}")
            argv.append(service)
        if req.get("verbose"):
            argv.append("--verbose")
        return argv

    if cmd == "list":
        argv = [COXYZ_BIN, "list"]
        category = req.get("category")
        if category:
            if not isinstance(category, str) or not _CATEGORY_RE.match(category):
                raise ValueError(f"invalid category name: {category!r}")
            argv += ["--category", category]
        return argv

    raise ValueError(
        f"command not allowed: {cmd!r} (read-only: check, list; "
        f"mutating, relayed to admind: {', '.join(RELAYED)})"
    )


def _run(argv: list[str]) -> dict:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            shell=False,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                 "TERM": "dumb", "NO_COLOR": "1", "COLUMNS": "100",
                 # Never let a read-only command try to escalate: without this
                 # ensure_root() would re-exec through sudo.
                 "COXYZ_NO_SUDO": "1"},
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {TIMEOUT}s"}
    except OSError as exc:
        return {"ok": False, "error": f"could not run the command: {exc}"}
    return {
        "ok": True,
        "argv": argv[1:],
        # `check` exits non-zero when it finds drift: that is a result, not a
        # failure, and the caller must be able to tell them apart.
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:MAX_OUTPUT],
        "stderr": proc.stderr[:MAX_OUTPUT],
        "truncated": len(proc.stdout) > MAX_OUTPUT or len(proc.stderr) > MAX_OUTPUT,
    }


def _relay(req: dict) -> dict:
    """Forward a mutating request to the privileged daemon, unchanged.

    Deliberately a pass-through: re-validating here would create a second,
    drifting copy of the rules. admind is the authority, and it is the only
    process that can act.
    """
    # Pop before building the message: in `{**req, "op": req.pop("cmd")}` the
    # unpacking is evaluated first, so "cmd" would survive alongside "op".
    forwarded = dict(req)
    forwarded["op"] = forwarded.pop("cmd")
    payload = json.dumps(forwarded, ensure_ascii=False).encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(ADMIN_SOCKET)
            sock.sendall(payload + b"\n")
            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if chunk.endswith(b"\n"):
                    break
    except OSError as exc:
        return {"ok": False, "error": (
            f"privileged daemon unreachable ({ADMIN_SOCKET}): {exc}. "
            "Is coxyz-admind.socket started?"
        )}
    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        return {"ok": False, "error": "empty response from the privileged daemon."}
    try:
        return json.loads(raw)
    except ValueError as exc:
        return {"ok": False, "error": f"unreadable response from the daemon: {exc}"}


class Handler(socketserver.StreamRequestHandler):
    timeout = 15

    def handle(self) -> None:
        try:
            raw = self.rfile.readline(MAX_REQUEST)
            req = json.loads(raw.decode("utf-8"))
            if not isinstance(req, dict):
                raise ValueError("invalid JSON request (an object is expected)")
        except (ValueError, UnicodeDecodeError) as exc:
            resp = {"ok": False, "error": str(exc)}
        except OSError as exc:
            resp = {"ok": False, "error": f"reading the request: {exc}"}
        else:
            if req.get("cmd") in RELAYED:
                print(f"[coxyz-runnerd] relay {req.get('cmd')} {req.get('action', '')}",
                      flush=True)
                resp = _relay(req)
            else:
                try:
                    argv = _build_argv(req)
                except ValueError as exc:
                    resp = {"ok": False, "error": str(exc)}
                else:
                    print(f"[coxyz-runnerd] {' '.join(argv[1:])}", flush=True)
                    resp = _run(argv)
        try:
            self.wfile.write(json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n")
        except OSError:
            pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    if os.geteuid() == 0:
        sys.exit("[coxyz-runnerd] refusing to run as root: use the svc_mcprun account.")
    if not os.path.exists(COXYZ_BIN):
        sys.exit(f"[coxyz-runnerd] binary not found: {COXYZ_BIN}")

    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = Server(SOCKET_PATH, Handler)
    # 0660: the owner and its group. The MCP container carries that GID as a
    # supplementary group, so it can connect — and nothing else on the host can.
    os.chmod(SOCKET_PATH, 0o660)
    print(f"[coxyz-runnerd] listening on {SOCKET_PATH} (uid={os.geteuid()}), "
          f"admind at {ADMIN_SOCKET}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()
