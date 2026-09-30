"""The single gateway between the MCP container and the CLI.

v1 had two daemons: ``clixz-runnerd`` (unprivileged, read-only) relayed
mutations to ``clixz-admind`` (root, CAP_CHOWN/CAP_FOWNER/CAP_DAC_OVERRIDE) over
a second socket, with a plan store and a SHA-256 binding between what a human
approved and what got written.

The audit of 2026-08-29 found that ``mcp.coxyz.fr`` was published on the
internet. That made the chain internet → bearer token → runnerd → a root daemon
with DAC_OVERRIDE, to spare the only human on the machine from typing
``sudo clixz fix``. The trade was not worth it, so ``admind`` is gone.

What is left cannot write. Not "is not supposed to" — cannot: every mutating
verb is forwarded to the CLI with ``--plan``, which prints the commands it would
run and exits without touching anything, and the unit carries
``ReadOnlyPaths=/srv/docker``. The approval loop still exists; it goes through
the keyboard.

Protocol — one JSON object per connection, newline-terminated::

    {"cmd": "check", "service": "bitwarden"}
    {"cmd": "plan", "action": "fix", "service": "apps/atuin"}
"""

from __future__ import annotations

import json
import os
import re
import socketserver
import subprocess
import sys

from .config import env

CLIXZ_BIN = env("BIN", "/usr/local/bin/clixz")
SOCKET_PATH = env("MCPD_SOCKET", "/run/clixz-mcpd/clixz-mcpd.sock")
TIMEOUT = int(env("MCPD_TIMEOUT", "60"))
MAX_OUTPUT = 256 * 1024
MAX_REQUEST = 64 * 1024

_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$")
_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Read-only verbs, run as-is.
READ_COMMANDS = ("ls", "show", "check", "manifest", "exposed", "config")
# Mutating verbs. Never run as themselves — always with --plan, which prints
# what would happen and writes nothing.
PLAN_ACTIONS = ("new", "fix", "rm")


class RequestError(ValueError):
    """The request is malformed or not allowed. The message is caller-facing."""


def _service(value: object, *, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise RequestError("a 'service' is required")
        return None
    # str(42) would satisfy the regex, so a non-string is refused rather than
    # coerced into something that happens to look valid.
    if not isinstance(value, str) or not _SERVICE_RE.match(value):
        raise RequestError(f"invalid service name: {value!r}")
    return value


def build_argv(req: dict) -> list[str]:
    """Translate a validated request into argv, or raise :class:`RequestError`.

    All of the safety lives here: the subcommand comes from a closed set, every
    variable argument is regex-checked, and nothing reaches a shell.
    """
    cmd = req.get("cmd")

    if cmd in READ_COMMANDS:
        argv = [CLIXZ_BIN, str(cmd), "--json"]
        if cmd in ("check", "show"):
            service = _service(req.get("service"), required=(cmd == "show"))
            if service:
                argv.append(service)
        if cmd == "ls":
            category = req.get("category")
            if category is not None:
                if not isinstance(category, str) or not _CATEGORY_RE.match(category):
                    raise RequestError(f"invalid category name: {category!r}")
                argv += ["--category", category]
        if cmd == "manifest":
            argv.append("--dry-run")
        return argv

    if cmd == "plan":
        action = req.get("action")
        if action not in PLAN_ACTIONS:
            raise RequestError(
                f"unknown action: {action!r} (known: {', '.join(PLAN_ACTIONS)})"
            )
        service = _service(req.get("service"), required=(action != "fix"))
        argv = [CLIXZ_BIN, str(action)]
        if service:
            argv.append(service)
        # --plan is what makes this daemon safe to expose: the CLI prints the
        # commands it would run and exits without writing.
        argv += ["--plan", "--json"]
        return argv

    raise RequestError(
        f"command not allowed: {cmd!r} (read: {', '.join(READ_COMMANDS)}; "
        f"plan: {', '.join(PLAN_ACTIONS)})"
    )


def run(argv: list[str]) -> dict:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=TIMEOUT, shell=False,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1", "COLUMNS": "100",
                # Without this, a command needing root would try to re-exec
                # through sudo — from a daemon that must never gain privilege.
                "CLIXZ_NO_SUDO": "1",
            },
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {TIMEOUT}s"}
    except OSError as exc:
        return {"ok": False, "error": f"could not run the command: {exc}"}
    return {
        "ok": True,
        "argv": argv[1:],
        # `check` exits non-zero on drift: that is a result, not a failure, and
        # the caller must be able to tell the two apart.
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:MAX_OUTPUT],
        "stderr": proc.stderr[:MAX_OUTPUT],
        "truncated": len(proc.stdout) > MAX_OUTPUT or len(proc.stderr) > MAX_OUTPUT,
    }


def handle(raw: bytes) -> dict:
    try:
        req = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"ok": False, "error": f"malformed request: {exc}"}
    if not isinstance(req, dict):
        return {"ok": False, "error": "malformed request: an object is expected"}
    try:
        argv = build_argv(req)
    except RequestError as exc:
        return {"ok": False, "error": str(exc)}
    return run(argv)


class Handler(socketserver.StreamRequestHandler):
    timeout = 15

    def handle(self) -> None:
        try:
            raw = self.rfile.readline(MAX_REQUEST)
        except OSError as exc:
            response = {"ok": False, "error": f"reading the request: {exc}"}
        else:
            response = handle(raw)
        try:
            self.wfile.write(
                json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
            )
        except OSError:
            pass  # the client hung up; nothing useful left to do


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16


def main() -> None:
    path = SOCKET_PATH
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(path):
        os.unlink(path)

    server = Server(path, Handler)
    # 0660: the MCP container carries the daemon's gid and can connect; nothing
    # else on the host can. The socket is the only surface this daemon has.
    os.chmod(path, 0o660)
    print(f"[clixz-mcpd] listening on {path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if os.path.exists(path):
            os.unlink(path)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
