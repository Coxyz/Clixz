"""The single gateway between the MCP container and the host.

v1 had two daemons: ``clixz-runnerd`` (unprivileged, read-only) relayed
mutations to ``clixz-admind`` (root, CAP_CHOWN/CAP_FOWNER/CAP_DAC_OVERRIDE),
a long-running root process reachable from an internet-published MCP server.
2.0 removed it: mutations could only be *planned*, and the operator typed the
command.

2.3 brings application back, differently. This daemon still cannot write — the
unit keeps ``ProtectSystem=strict`` and ``ReadOnlyPaths=/srv/docker`` — and it
holds no privilege. What it gained is a second socket to talk to:
``clixz-apply``, a root process systemd starts for one request and that exits
with it. Service plans, applies, the plan store, the live ``exposed`` and the
todo writes go there; reads still run the CLI here, unprivileged. The applier
validates everything again: this daemon is a filter for clarity, not the
security boundary on that path.

Protocol — one JSON object per connection, newline-terminated::

    {"cmd": "check", "service": "bitwarden"}                  → CLI, here
    {"cmd": "plan", "action": "edit", "service": "apps/atuin",
     "compose": "services: …"}                                → clixz-apply
    {"cmd": "apply", "plan_id": "0a1b2c3d"}                   → clixz-apply
    {"cmd": "plan", "action": "category-add", "name": "media"} → CLI --plan, here
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
from typing import Any

from . import __version__
from .category import ACCOUNT_NAME_RE, CATEGORY_NAME_RE
from .config import env
from .plans import MAX_COMPOSE, MAX_SERVICE_YAML, PLAN_ID_RE, STACK_RE
from .repo import REPO_NAME_RE, REPO_URL_RE
from .todo import STATES

CLIXZ_BIN = env("BIN", "/usr/local/bin/clixz")
SOCKET_PATH = env("MCPD_SOCKET", "/run/clixz-mcpd/clixz-mcpd.sock")
APPLY_SOCKET = env("APPLY_SOCKET", "/run/clixz-apply.sock")
TIMEOUT = int(env("MCPD_TIMEOUT", "60"))
APPLY_TIMEOUT = int(env("APPLY_TIMEOUT", "120"))
MAX_OUTPUT = 256 * 1024
MAX_REQUEST = 512 * 1024
MAX_RESPONSE = 4 * 1024 * 1024

_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$")
_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Read-only verbs, run as-is through the CLI, unprivileged.
READ_COMMANDS = ("ls", "show", "check", "manifest", "config", "rules", "repos",
                 "categories", "todo", "todo-show")
# Service plans: computed, stored and applied by clixz-apply.
APPLIED_ACTIONS = ("new", "edit", "fix", "rm")
# Mutations on something else than a service: planned by the CLI, never applied.
NAMED_PLAN_ACTIONS = {
    "category-add": ["category", "add"],
    "repo-add": ["repo", "add"],
    "repo-rm": ["repo", "rm"],
}
# Everything else that goes to clixz-apply as it is.
RELAYED = ("plans", "plan-show", "plan-drop", "apply", "exposed",
           "todo-add", "todo-edit", "todo-rm")
# Read verbs that are a subcommand of a group.
_GROUP_READS = {"repos": ["repo", "ls"], "categories": ["category", "ls"]}


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


def _checked(req: dict, key: str, pattern: re.Pattern[str], *, required: bool) -> str | None:
    value = req.get(key)
    if value is None:
        if required:
            raise RequestError(f"a '{key}' is required")
        return None
    if not isinstance(value, str) or not pattern.match(value):
        raise RequestError(f"invalid {key}: {value!r}")
    return value


def _text(req: dict, key: str, limit: int, *, required: bool = False) -> str | None:
    value = req.get(key)
    if value is None:
        if required:
            raise RequestError(f"a '{key}' is required")
        return None
    if not isinstance(value, str):
        raise RequestError(f"'{key}' must be a string")
    if len(value.encode("utf-8")) > limit:
        raise RequestError(f"'{key}' is larger than {limit // 1024} KiB")
    return value


def _item_id(req: dict) -> int:
    value = req.get("id")
    if not isinstance(value, int) or isinstance(value, bool):
        raise RequestError(f"'id' must be an item number, got {value!r}")
    return value


def _named_plan(action: str, req: dict) -> list[str]:
    argv = [CLIXZ_BIN, *NAMED_PLAN_ACTIONS[action]]
    if action == "category-add":
        argv.append(_checked(req, "name", CATEGORY_NAME_RE, required=True))
        account = _checked(req, "account", ACCOUNT_NAME_RE, required=False)
        if account:
            argv += ["--account", account]
    else:
        argv.append(_checked(req, "name", REPO_NAME_RE, required=True))
        if action == "repo-add":
            url = _checked(req, "url", REPO_URL_RE, required=False)
            if url:
                argv += ["--url", url]
    return [*argv, "--plan", "--json"]


def build_argv(req: dict) -> list[str]:
    """Translate a validated CLI request into argv, or raise :class:`RequestError`.

    The subcommand comes from a closed set, every variable argument is
    regex-checked, and nothing reaches a shell.
    """
    cmd = req.get("cmd")

    if cmd in _GROUP_READS:
        return [CLIXZ_BIN, *_GROUP_READS[cmd], "--json"]

    if cmd == "todo":
        state = req.get("state")
        if state is None:
            return [CLIXZ_BIN, "todo", "ls", "--all", "--json"]
        if state not in STATES:
            raise RequestError(f"invalid state: {state!r} (known: {', '.join(STATES)})")
        return [CLIXZ_BIN, "todo", "ls", "--state", str(state), "--json"]
    if cmd == "todo-show":
        return [CLIXZ_BIN, "todo", "show", str(_item_id(req)), "--json"]

    if cmd in READ_COMMANDS:
        argv = [CLIXZ_BIN, str(cmd), "--json"]
        if cmd in ("check", "show"):
            service = _service(req.get("service"), required=(cmd == "show"))
            if service:
                argv.append(service)
        # The MCP tool has always offered `verbose`; until 2.2 it was dropped here.
        if cmd == "check" and req.get("verbose") is True:
            argv.append("--verbose")
        if cmd == "ls":
            category = req.get("category")
            if category is not None:
                if not isinstance(category, str) or not _CATEGORY_RE.match(category):
                    raise RequestError(f"invalid category name: {category!r}")
                argv += ["--category", category]
        if cmd == "manifest":
            argv.append("--dry-run")
        return argv

    if cmd == "plan" and req.get("action") in NAMED_PLAN_ACTIONS:
        return _named_plan(str(req["action"]), req)

    raise RequestError(
        f"command not allowed: {cmd!r} (read: {', '.join(READ_COMMANDS)}; "
        f"plan: {', '.join((*APPLIED_ACTIONS, *NAMED_PLAN_ACTIONS))}; "
        f"relayed: {', '.join(RELAYED)})"
    )


def _relay_payload(req: dict) -> dict:
    """Keep the fields clixz-apply understands, checked; drop everything else."""
    cmd = req["cmd"]
    out: dict[str, Any] = {"cmd": cmd}
    if cmd == "plan":
        action = req["action"]
        out["action"] = action
        service = _service(req.get("service"), required=(action != "fix"))
        if service:
            out["service"] = service
        if action in ("new", "edit"):
            for key, limit in (("compose", MAX_COMPOSE), ("service_yaml", MAX_SERVICE_YAML)):
                value = _text(req, key, limit)
                if value is not None:
                    out[key] = value
        if req.get("stack") is not None:
            if action != "new":
                raise RequestError("'stack' only goes with 'new'")
            out["stack"] = _checked(req, "stack", STACK_RE, required=True)
    elif cmd in ("apply", "plan-show", "plan-drop"):
        out["plan_id"] = _checked(req, "plan_id", PLAN_ID_RE, required=True)
    elif cmd in ("todo-add", "todo-edit"):
        if cmd == "todo-edit":
            out["id"] = _item_id(req)
        for key in ("title", "description", "state"):
            value = _text(req, key, 32 * 1024, required=(cmd == "todo-add" and key == "title"))
            if value is not None:
                out[key] = value
    elif cmd == "todo-rm":
        out["id"] = _item_id(req)
    return out


def route(req: dict) -> tuple[str, Any]:
    """``("cli", argv)``, ``("relay", payload)`` or ``("local", answer)``."""
    cmd = req.get("cmd")
    if cmd == "version":
        return "local", {"ok": True, "version": __version__}
    if (cmd == "plan" and req.get("action") in APPLIED_ACTIONS) or cmd in RELAYED:
        return "relay", _relay_payload(req)
    return "cli", build_argv(req)


def access() -> dict:
    """What a caller on the socket can ask for, and where each request goes.

    Built by running :func:`route` on a sample of each request rather than
    written out by hand, so `clixz mcp` cannot drift from what the daemon does.
    """
    options = {"check": "[service] [--verbose]", "ls": "[--category <category>]",
               "todo": "[--state <state>]"}
    samples: dict[str, dict] = {"show": {"service": "category/service"}, "todo-show": {"id": 1}}
    read = []
    for cmd in READ_COMMANDS:
        argv = build_argv({"cmd": cmd, **samples.get(cmd, {})})[1:]
        read.append({"request": cmd,
                     "runs": " ".join(["clixz", *argv, options.get(cmd, "")]).strip()})

    plan_samples = {"category-add": {"name": "name"}, "repo-add": {"name": "name"},
                    "repo-rm": {"name": "name"}}
    plan_options = {"category-add": "[--account <account>]", "repo-add": "[--url <url>]"}
    plan = []
    for action in NAMED_PLAN_ACTIONS:
        argv = build_argv({"cmd": "plan", "action": action, **plan_samples[action]})[1:]
        plan.append({"request": action,
                     "runs": " ".join(["clixz", *argv, plan_options.get(action, "")]).strip()})

    relay = [{"request": f"plan {action}",
              "does": "compute and store a plan (clixz-apply)"} for action in APPLIED_ACTIONS]
    does = {"plans": "list the stored plans", "plan-show": "one stored plan",
            "plan-drop": "delete a stored plan", "apply": "apply a stored plan, once",
            "exposed": "read the proxy database, live", "todo-add": "add a todo item",
            "todo-edit": "edit a todo item", "todo-rm": "delete a todo item"}
    relay += [{"request": cmd, "does": does[cmd]} for cmd in RELAYED]
    return {"socket": SOCKET_PATH, "apply_socket": APPLY_SOCKET,
            "read": read, "plan": plan, "relay": relay}


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


def relay(payload: dict) -> dict:
    """Send one request to clixz-apply and return its answer."""
    if not os.path.exists(APPLY_SOCKET):
        return {"ok": False,
                "error": f"clixz-apply is not installed ({APPLY_SOCKET} is missing): "
                         "run `sudo clixz daemon install` on the host"}
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
    chunks: list[bytes] = []
    size = 0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(APPLY_TIMEOUT)
            sock.connect(APPLY_SOCKET)
            sock.sendall(data)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_RESPONSE:
                    return {"ok": False, "error": "clixz-apply answered more than 4 MiB"}
                if chunk.endswith(b"\n"):
                    break
    except (OSError, socket.timeout) as exc:
        return {"ok": False, "error": f"clixz-apply unreachable: {exc}"}
    try:
        answer = json.loads(b"".join(chunks).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"ok": False, "error": f"unreadable answer from clixz-apply: {exc}"}
    return answer if isinstance(answer, dict) else {"ok": False, "error": "bad answer"}


def handle(raw: bytes) -> dict:
    try:
        req = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"ok": False, "error": f"malformed request: {exc}"}
    if not isinstance(req, dict):
        return {"ok": False, "error": "malformed request: an object is expected"}
    try:
        kind, value = route(req)
    except RequestError as exc:
        return {"ok": False, "error": str(exc)}
    if kind == "local":
        return value
    if kind == "relay":
        return relay(value)
    return run(value)


# ─── version ─────────────────────────────────────────────────────────────────

def installed_version() -> str | None:
    """The version on disk now — not the one this process imported."""
    importlib.invalidate_caches()
    try:
        return importlib.metadata.version("clixz")
    except importlib.metadata.PackageNotFoundError:
        return None


def version_changed() -> bool:
    current = installed_version()
    return current is not None and current != __version__


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
    # How often to look for an upgrade. An upgrade that leaves this process
    # running has upgraded the CLI and not the gateway: when the installed
    # version moves, the daemon leaves and systemd (Restart=always) starts the
    # new code — whichever installer did the upgrade.
    check_interval = 30.0
    _last_check = 0.0
    _leaving = False

    def service_actions(self) -> None:
        now = time.monotonic()
        if self._leaving or now - self._last_check < self.check_interval:
            return
        self._last_check = now
        if version_changed():
            self._leaving = True
            print(f"[clixz-mcpd] clixz {installed_version()} is installed, this process runs "
                  f"{__version__}: exiting so that systemd restarts it", flush=True)
            threading.Thread(target=self.shutdown, daemon=True).start()


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
    print(f"[clixz-mcpd] {__version__} listening on {path}", flush=True)
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
