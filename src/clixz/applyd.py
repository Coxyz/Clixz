"""``clixz-apply``: the root process that writes on behalf of the MCP gateway.

systemd starts one per connection on ``/run/clixz-apply.sock``
(``clixz-apply.socket``, ``Accept=yes``): the connection is this process's
stdin and stdout, it reads one JSON request, answers one JSON line and exits.
Nothing privileged runs between requests, and every request runs the clixz
installed at that moment — an upgrade never leaves a stale root process.

Only ``clixz-mcpd`` can connect (the socket is ``root:svc_mcprun 0660`` and is
not mounted in the MCP container). This process trusts it no more than it
trusts the internet: every field is validated again here, and the requests it
accepts are a closed set —

    plan        compute a plan for new / edit / fix / rm; store it unless blocked
    apply       apply a stored plan, once, if it still describes the disk
    plans       list the stored plans
    plan-show   one stored plan, contents included
    plan-drop   delete a stored plan
    exposed     read the reverse proxy database, live
    todo-add / todo-edit / todo-rm

Each request leaves one line in the unit's journal.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

from . import plans
from .config import Config, load_config
from .npm import exposure_payload
from .todo import TodoError, TodoStore

MAX_REQUEST = 512 * 1024


class RequestError(ValueError):
    """The request is malformed. The message is caller-facing."""


def _log(message: str) -> None:
    print(f"[clixz-apply] {message}", file=sys.stderr, flush=True)


def _item_id(req: dict) -> int:
    value = req.get("id")
    # bool is an int in Python; `true` is not an item number.
    if not isinstance(value, int) or isinstance(value, bool):
        raise RequestError(f"'id' must be an item number, got {value!r}")
    return value


def _optional_str(req: dict, key: str) -> str | None:
    value = req.get(key)
    if value is not None and not isinstance(value, str):
        raise RequestError(f"'{key}' must be a string")
    return value


def _todo(config: Config) -> TodoStore:
    return TodoStore(config.state.todo_file, group=config.state.group)


def _plan(config: Config, req: dict) -> dict:
    plan = plans.compute(config, plans.Request.from_dict(req))
    if plan.blocked:
        _log(f"plan {plan.action} {plan.target}: blocked ({len(plan.blocked)} reason(s))")
        return {"ok": True, "plan": plan.to_dict()}
    stored = plans.save(config, plan, origin="mcp")
    _log(f"plan {stored.id}: {stored.action} {stored.target}, {len(stored.commands)} command(s)")
    return {"ok": True, "plan": stored.to_dict()}


def _apply(config: Config, req: dict) -> dict:
    outcome = plans.apply(config, req.get("plan_id"))  # type: ignore[arg-type]
    _log(f"apply {outcome.plan.id}: {outcome.plan.action} {outcome.plan.target} — "
         f"{'ok' if outcome.ok else 'FAILED'}, {len(outcome.executed)} command(s)"
         + (f", {len(outcome.warnings)} warning(s)" if outcome.warnings else ""))
    return outcome.to_dict()


def _plans(config: Config, req: dict) -> dict:
    return {"ok": True, "plans": [p.summary() for p in plans.list_plans(config)]}


def _plan_show(config: Config, req: dict) -> dict:
    return {"ok": True, "plan": plans.load(config, req.get("plan_id")).to_dict()}  # type: ignore[arg-type]


def _plan_drop(config: Config, req: dict) -> dict:
    plan = plans.drop(config, req.get("plan_id"))  # type: ignore[arg-type]
    _log(f"plan {plan.id} dropped ({plan.action} {plan.target})")
    return {"ok": True, "dropped": plan.summary()}


def _exposed(config: Config, req: dict) -> dict:
    return {"ok": True, **exposure_payload(config)}


def _todo_add(config: Config, req: dict) -> dict:
    title = req.get("title")
    item = _todo(config).add(title,  # type: ignore[arg-type]
                             _optional_str(req, "description") or "",
                             _optional_str(req, "state") or "todo")
    _log(f"todo #{item.id} added")
    return {"ok": True, "item": item.to_dict()}


def _todo_edit(config: Config, req: dict) -> dict:
    item = _todo(config).update(_item_id(req), title=_optional_str(req, "title"),
                                description=_optional_str(req, "description"),
                                state=_optional_str(req, "state"))
    _log(f"todo #{item.id} edited")
    return {"ok": True, "item": item.to_dict()}


def _todo_rm(config: Config, req: dict) -> dict:
    item = _todo(config).remove(_item_id(req))
    _log(f"todo #{item.id} removed")
    return {"ok": True, "removed": item.to_dict()}


COMMANDS: dict[str, Callable[[Config, dict], dict]] = {
    "plan": _plan, "apply": _apply, "plans": _plans, "plan-show": _plan_show,
    "plan-drop": _plan_drop, "exposed": _exposed,
    "todo-add": _todo_add, "todo-edit": _todo_edit, "todo-rm": _todo_rm,
}


def handle(raw: bytes, config: Config) -> dict[str, Any]:
    if len(raw) > MAX_REQUEST:
        return {"ok": False, "error": f"request larger than {MAX_REQUEST // 1024} KiB"}
    try:
        req = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"ok": False, "error": f"malformed request: {exc}"}
    if not isinstance(req, dict):
        return {"ok": False, "error": "malformed request: an object is expected"}
    command = COMMANDS.get(req.get("cmd"))  # type: ignore[arg-type]
    if command is None:
        return {"ok": False,
                "error": f"command not allowed: {req.get('cmd')!r} (known: {', '.join(COMMANDS)})"}
    try:
        return command(config, req)
    except (plans.PlanError, TodoError, RequestError) as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        _log(f"{req.get('cmd')}: {exc}")
        return {"ok": False, "error": f"{req.get('cmd')} failed: {exc}"}


def main() -> None:
    raw = sys.stdin.buffer.readline(MAX_REQUEST + 1)
    try:
        config, _ = load_config()
    except (ValueError, OSError) as exc:
        response: dict[str, Any] = {"ok": False, "error": f"cannot load the config: {exc}"}
    else:
        response = handle(raw.rstrip(b"\n"), config)
    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":  # pragma: no cover
    main()
