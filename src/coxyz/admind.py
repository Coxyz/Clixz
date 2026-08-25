"""Privileged daemon for the two mutating operations that genuinely need root.

Why a daemon rather than a sudoers rule
---------------------------------------
``create`` and ``archive`` chown to the ``svc_*`` accounts and set ACLs, so they
need ``CAP_CHOWN``/``CAP_FOWNER``. The obvious alternative — a ``sudoers`` entry
— is worse: a wildcard like ``coxyz create *`` matches spaces, so it silently
authorises every option the CLI will ever grow (``--config /tmp/evil.yaml``…).
sudo's wildcards are not an argument validator. Here the contract is a typed
JSON message, so the whole class of argument-injection bugs does not exist.

There is deliberately **no delete opcode**. Destroying a service stays a TTY
gesture (``clixz archive --force``); it is not merely refused here, it is not
expressible over the protocol.

Two-step apply
--------------
``plan`` validates and returns a ``plan_id`` plus the SHA-256 of the exact bytes
that would be written. ``apply`` replays that hash and is refused if the content
no longer matches. Without this binding an agent could get content A approved by
a human and then apply content B — the plan/confirm pattern is worthless if the
confirmation is not bound to what was reviewed.

Callers are authenticated by ``SO_PEERCRED`` (kernel-provided uid), not by the
socket mode alone, and must match ``COXYZ_ADMIN_ALLOWED_UID``.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import socketserver
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .archive import archive_service, snapshot_file
from .config import load_config
from .policy import resolve_service
from .scaffold import CreateRequest, create_service
from .spec import (
    SPEC_FILENAME,
    SpecError,
    apply_patch,
    load_spec,
    render_compose,
    spec_from_dict,
    spec_json,
    validate,
)
from .system import CommandRunner, detect_acl_support, principal_exists

SOCKET_PATH = os.environ.get("COXYZ_ADMIN_SOCKET", "/run/coxyz-admin/coxyz-admin.sock")
AUDIT_LOG = Path(os.environ.get("COXYZ_ADMIN_LOG", "/var/log/coxyz-admind.log"))
PLAN_TTL = int(os.environ.get("COXYZ_ADMIN_PLAN_TTL", "300"))
MAX_REQUEST = 256 * 1024
MAX_PLANS = 32

# Services whose compose drives the host itself. Mutating any of them from an
# automated caller is a foot-gun with no upside: npm is the reverse proxy that
# terminates the very connection carrying the request, mcp is this system, and
# infra/* holds the orchestrator that deploys everything else.
PROTECTED = (
    ("apps", "mcp"),
    ("apps", "code-boxyz"),
    ("network", "npm"),
)
PROTECTED_CATEGORIES = ("infra",)


class AdminError(Exception):
    """A refusal to report to the caller. The message is caller-facing."""


# ─── audit trail ──────────────────────────────────────────────────────────────

def _audit(event: str, **fields: Any) -> None:
    """Append one JSON line. Never raises: a logging failure must not block."""
    line = json.dumps(
        {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
         "event": event, **fields},
        ensure_ascii=False,
    )
    try:
        with AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        print(f"[coxyz-admind] (audit write failed) {line}", flush=True)
    else:
        print(f"[coxyz-admind] {line}", flush=True)


# ─── plan store ───────────────────────────────────────────────────────────────

class PlanStore:
    """Short-lived plans, each bound to the hash of the content it approved."""

    def __init__(self) -> None:
        self._plans: dict[str, dict] = {}

    def _sweep(self) -> None:
        now = time.monotonic()
        for pid in [p for p, v in self._plans.items() if v["expires"] < now]:
            del self._plans[pid]

    def put(self, payload: dict) -> str:
        self._sweep()
        if len(self._plans) >= MAX_PLANS:
            raise AdminError("Too many pending plans; retry shortly.")
        pid = secrets.token_urlsafe(12)
        self._plans[pid] = {**payload, "expires": time.monotonic() + PLAN_TTL}
        return pid

    def take(self, plan_id: str, digest: str) -> dict:
        self._sweep()
        plan = self._plans.pop(plan_id, None)
        if plan is None:
            raise AdminError("Unknown or expired plan — run the plan step again.")
        if not secrets.compare_digest(plan["hash"], digest):
            raise AdminError(
                "The hash does not match the approved plan. Refusing to apply "
                "content that differs from what was reviewed."
            )
        return plan


PLANS = PlanStore()


# ─── helpers ──────────────────────────────────────────────────────────────────

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _guard_target(category: str, service: str) -> None:
    if category in PROTECTED_CATEGORIES or (category, service) in PROTECTED:
        raise AdminError(
            f"{category}/{service} is protected and cannot be modified by an "
            "automated caller. Use the CLI directly."
        )


def _ctx():
    cfg, _ = load_config(None)
    acl = detect_acl_support(cfg.root_dir)
    principals = {
        name: principal_exists(p.name, p.kind)
        for name, p in cfg.settings.principals.items()
    }
    return cfg, acl, principals


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


# ─── operations ───────────────────────────────────────────────────────────────

def _plan_create(req: dict) -> dict:
    cfg, _, _ = _ctx()
    spec = validate(spec_from_dict(req.get("spec")), cfg)
    _guard_target(spec.category, spec.service)
    svc_path = cfg.root_dir / spec.category / spec.service
    if svc_path.exists():
        raise AdminError(f"{spec.category}/{spec.service} already exists.")

    compose = render_compose(spec, cfg)
    payload = {
        "action": "create", "category": spec.category, "service": spec.service,
        "spec": spec_json(spec), "compose": compose, "hash": _sha256(compose),
    }
    return {
        "plan_id": PLANS.put(payload), "hash": payload["hash"],
        "action": "create", "target": f"{spec.category}/{spec.service}",
        "compose": compose, "spec": payload["spec"],
    }


def _plan_update(req: dict) -> dict:
    cfg, _, _ = _ctx()
    category, service = _resolve(cfg, req)
    _guard_target(category, service)

    current = load_spec(cfg, category, service)
    merged = validate(apply_patch(current, req.get("patch")), cfg)
    compose = render_compose(merged, cfg)
    svc_path = cfg.root_dir / category / service
    payload = {
        "action": "update", "category": category, "service": service,
        "spec": spec_json(merged), "compose": compose, "hash": _sha256(compose),
    }
    return {
        "plan_id": PLANS.put(payload), "hash": payload["hash"],
        "action": "update", "target": f"{category}/{service}",
        "compose": compose, "spec": payload["spec"],
        "previous_compose": _read_text(svc_path / "compose.yaml"),
        "previous_spec": _read_text(svc_path / SPEC_FILENAME),
    }


def _plan_archive(req: dict) -> dict:
    cfg, _, _ = _ctx()
    category, service = _resolve(cfg, req)
    _guard_target(category, service)
    svc_path = cfg.root_dir / category / service
    # Hash the identity: there is no content to review, but apply must still be
    # bound to the exact target the plan named.
    digest = _sha256(f"archive:{category}/{service}")
    payload = {"action": "archive", "category": category, "service": service, "hash": digest}
    return {
        "plan_id": PLANS.put(payload), "hash": digest,
        "action": "archive", "target": f"{category}/{service}", "path": str(svc_path),
    }


def _resolve(cfg, req: dict) -> tuple[str, str]:
    name = str(req.get("service") or "").strip()
    if not name:
        raise AdminError("Missing 'service'.")
    try:
        category, service, _ = resolve_service(cfg, name)
    except ValueError as exc:
        raise AdminError(str(exc)) from None
    return category, service


def _write_generated(cfg, acl, principals, category: str, service: str,
                     compose: str, spec_text: str) -> list[list[str]]:
    """Write compose.yaml then spec.json, each brought to its configured perms."""
    from .policy import plan_path

    svc_path = cfg.root_dir / category / service
    runner = CommandRunner(dry_run=False)
    for path, content, rule_name in (
        (svc_path / "compose.yaml", compose, "compose_file"),
        (svc_path / SPEC_FILENAME, spec_text, "spec_file"),
    ):
        runner.write_file(path, content)
        rule = cfg.rule_or_default(rule_name)
        owner = rule.owner or cfg.category(category).owner_spec
        for cmd in plan_path(path, rule, owner, cfg, is_dir=False,
                             acl_enabled=acl, principals_available=principals):
            runner.run(cmd)
    return runner.executed


def _apply(plan: dict) -> dict:
    cfg, acl, principals = _ctx()
    category, service = plan["category"], plan["service"]
    _guard_target(category, service)

    if plan["action"] == "archive":
        result = archive_service(cfg, category, service, dry_run=False, force=False)
        return {"archived_to": str(result.destination)}

    snapshot = None
    if plan["action"] == "create":
        create_service(cfg, CreateRequest(category=category, service=service),
                       dry_run=False, acl_enabled=acl, principals_available=principals)
    else:
        # Keep the superseded compose, so a bad patch stays recoverable.
        existing = cfg.root_dir / category / service / "compose.yaml"
        if existing.is_file():
            snapshot = snapshot_file(cfg, category, service, existing, dry_run=False)

    commands = _write_generated(cfg, acl, principals, category, service,
                                plan["compose"], plan["spec"])
    return {"commands": len(commands),
            "snapshot": str(snapshot) if snapshot else None}


_PLAN_OPS = {"create": _plan_create, "update": _plan_update, "archive": _plan_archive}


def handle(req: Any) -> dict:
    if not isinstance(req, dict):
        raise AdminError("A JSON object is expected.")
    op = req.get("op")

    if op == "plan":
        action = req.get("action")
        if action not in _PLAN_OPS:
            raise AdminError(
                f"Unknown action {action!r}. Available: {', '.join(sorted(_PLAN_OPS))}. "
                "Deletion is not available over this protocol."
            )
        return _PLAN_OPS[action](req)

    if op == "apply":
        plan_id, digest = req.get("plan_id"), req.get("hash")
        if not isinstance(plan_id, str) or not isinstance(digest, str):
            raise AdminError("'apply' requires 'plan_id' and 'hash'.")
        plan = PLANS.take(plan_id, digest)
        result = _apply(plan)
        return {"applied": True, "action": plan["action"],
                "target": f"{plan['category']}/{plan['service']}", **result}

    raise AdminError(f"Unknown op {op!r}. Available: plan, apply.")


# ─── server ───────────────────────────────────────────────────────────────────

def _peer_uid(sock: socket.socket) -> int:
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", creds)
    return uid


def _allowed_uid() -> int | None:
    raw = os.environ.get("COXYZ_ADMIN_ALLOWED_UID", "").strip()
    return int(raw) if raw else None


class Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self) -> None:
        allowed = _allowed_uid()
        try:
            uid = _peer_uid(self.connection)
        except OSError:
            uid = -1
        # The socket mode already restricts who can connect; SO_PEERCRED is what
        # the kernel guarantees, so the decision is taken on that.
        if allowed is not None and uid != allowed:
            _audit("rejected", reason="peer uid", uid=uid)
            self._reply({"ok": False, "error": "Caller not authorised."})
            return

        try:
            raw = self.rfile.readline(MAX_REQUEST)
            req = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._reply({"ok": False, "error": f"Malformed request: {exc}"})
            return
        except OSError as exc:
            _audit("read_error", error=str(exc))
            return

        op = req.get("op") if isinstance(req, dict) else None
        try:
            result = handle(req)
        except (AdminError, SpecError) as exc:
            _audit("refused", uid=uid, op=op, error=str(exc))
            self._reply({"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the caller
            _audit("failed", uid=uid, op=op, error=f"{type(exc).__name__}: {exc}")
            self._reply({"ok": False, "error": f"Internal error: {type(exc).__name__}"})
        else:
            _audit("ok", uid=uid, op=op,
                   target=result.get("target"), plan_id=result.get("plan_id"))
            self._reply({"ok": True, **result})

    def _reply(self, payload: dict) -> None:
        try:
            self.wfile.write(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")
        except OSError:
            pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: str, handler, *, inherited: socket.socket | None = None):
        if inherited is not None:
            # systemd socket activation: adopt the listening fd rather than bind.
            socketserver.BaseServer.__init__(self, path, handler)
            self.socket = inherited
        else:
            super().__init__(path, handler)


def _inherited_socket() -> socket.socket | None:
    """The listening fd handed over by systemd, when socket-activated."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    if int(os.environ.get("LISTEN_FDS", "0")) < 1:
        return None
    return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=3)


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("[coxyz-admind] must run as root (it chowns and sets ACLs).")

    inherited = _inherited_socket()
    if inherited is None:
        os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
        server = Server(SOCKET_PATH, Handler)
        os.chmod(SOCKET_PATH, 0o660)
    else:
        server = Server(SOCKET_PATH, Handler, inherited=inherited)

    _audit("started", socket=SOCKET_PATH, allowed_uid=_allowed_uid(),
           activated=inherited is not None)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if inherited is None and os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()
