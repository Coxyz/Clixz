"""Plans: computed, stored by root, recomputed and checked before they apply."""

from __future__ import annotations

import dataclasses
import grp
import json
import os
import pwd
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from clixz import plans
from clixz.config import parse_config
from clixz.komodo import KomodoError
from clixz.plans import PlanError, Request
from clixz.rules import Ignore, Policy, load_policy
from clixz.scaffold import CreateRequest, create_service

COMPOSE = "services:\n  demo:\n    image: nginx:1.27\n    restart: unless-stopped\n"
PRIVILEGED = "services:\n  demo:\n    image: nginx:1.27\n    privileged: true\n"
SERVICE = ("schema: 1\nname: Demo\nicon: x\ndescription: A demo\npublic: true\n")


def _me() -> tuple[str, str]:
    return pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name


class PlanTestCase(unittest.TestCase):
    komodo = False

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "tree"
        self.root.mkdir()
        user, group = _me()
        raw = {
            "root_dir": str(self.root),
            "categories": {"apps": {"user": user, "group": group},
                           "automation": {"user": user, "group": group}},
            "rules": {"dir": {"mode": "750"}, "file": {"mode": "640"},
                      "env": {"mode": "600", "owner": f"{user}:{group}"}},
            "api": {"manifest": str(self.base / "etc" / "manifest.json")},
            "state": {"dir": str(self.base / "state")},
        }
        if self.komodo:
            raw["komodo"] = {"credentials": str(self.base / "komodo.yaml")}
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLIXZ_STATE_DIR", None)
        self.config = parse_config(raw)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def existing(self, name: str = "demo", category: str = "apps") -> Path:
        create_service(self.config, CreateRequest(category, name, compose=COMPOSE,
                                                  service_yaml=SERVICE))
        return self.root / category / name

    def request(self, **kwargs) -> Request:
        return Request.from_dict(kwargs)


class RequestTests(unittest.TestCase):
    def test_an_unknown_action_is_refused(self) -> None:
        with self.assertRaises(PlanError):
            Request.from_dict({"action": "destroy", "service": "apps/x"})

    def test_types_are_checked_not_coerced(self) -> None:
        for raw in ({"action": "new", "service": 42},
                    {"action": "new", "service": "apps/x", "compose": ["a"]},
                    {"action": "fix", "service": "../etc"},
                    {"action": "new", "service": "apps/x", "stack": "bad name"},
                    "not even a mapping"):
            with self.assertRaises(PlanError, msg=repr(raw)):
                Request.from_dict(raw)

    def test_contents_are_capped(self) -> None:
        with self.assertRaises(PlanError):
            Request.from_dict({"action": "new", "service": "apps/x",
                               "compose": "x" * (128 * 1024 + 1)})
        with self.assertRaises(PlanError):
            Request.from_dict({"action": "edit", "service": "apps/x",
                               "service_yaml": "x" * (32 * 1024 + 1)})

    def test_contents_only_go_with_new_and_edit(self) -> None:
        with self.assertRaises(PlanError):
            Request.from_dict({"action": "rm", "service": "apps/x", "compose": COMPOSE})

    def test_new_edit_and_rm_need_a_service(self) -> None:
        for action in ("new", "edit", "rm"):
            with self.assertRaises(PlanError, msg=action):
                Request.from_dict({"action": action})
        self.assertIsNone(Request.from_dict({"action": "fix"}).service)

    def test_unknown_keys_are_ignored(self) -> None:
        self.assertEqual("fix", Request.from_dict({"action": "fix", "cmd": "plan"}).action)


class NewTests(PlanTestCase):
    def test_a_new_service_shows_its_files_as_a_diff_from_nothing(self) -> None:
        plan = plans.compute(self.config, self.request(action="new", service="apps/demo",
                                                       compose=COMPOSE, service_yaml=SERVICE))
        self.assertEqual([], plan.blocked)
        self.assertIn("+++ b/compose.yaml", plan.diff)
        self.assertIn("+    image: nginx:1.27", plan.diff)
        self.assertIn(["write_file", str(self.root / "apps" / "demo" / "compose.yaml")],
                      plan.commands)
        self.assertFalse((self.root / "apps").exists())

    def test_without_files_the_templates_are_planned(self) -> None:
        plan = plans.compute(self.config, self.request(action="new", service="apps/demo"))
        self.assertEqual([], plan.blocked)
        self.assertIn("cap_drop", plan.diff)

    def test_an_unaccepted_lint_error_blocks(self) -> None:
        plan = plans.compute(self.config, self.request(action="new", service="apps/demo",
                                                       compose=PRIVILEGED))
        self.assertTrue(any("privileged" in b for b in plan.blocked), plan.blocked)

    def test_a_lint_error_accepted_in_ignore_yaml_does_not_block(self) -> None:
        policy = Policy(ignores=(Ignore("apps/demo", ("privileged",), "needs /dev"),))
        config = dataclasses.replace(self.config, policy=policy)
        plan = plans.compute(config, self.request(action="new", service="apps/demo",
                                                  compose=PRIVILEGED))
        self.assertEqual([], plan.blocked)
        self.assertEqual("needs /dev", [x for x in plan.lint if x["rule"] == "privileged"][0]["ignored"])

    def test_a_compose_that_is_not_a_compose_blocks_without_raising(self) -> None:
        for text in ("services: []\n", "- a\n", "services: [oops\n", ""):
            plan = plans.compute(self.config, self.request(action="new", service="apps/demo",
                                                           compose=text))
            self.assertTrue(plan.blocked, repr(text))

    def test_an_invalid_service_yaml_blocks(self) -> None:
        plan = plans.compute(self.config, self.request(
            action="new", service="apps/demo", compose=COMPOSE, service_yaml="public: maybe\n"))
        self.assertTrue(any("service.yaml" in b for b in plan.blocked), plan.blocked)

    def test_an_existing_service_blocks(self) -> None:
        self.existing()
        plan = plans.compute(self.config, self.request(action="new", service="apps/demo",
                                                       compose=COMPOSE))
        self.assertTrue(plan.blocked)

    def test_an_unknown_category_or_bare_name_blocks(self) -> None:
        for service in ("media/demo", "demo"):
            plan = plans.compute(self.config, self.request(action="new", service=service))
            self.assertTrue(plan.blocked, service)

    def test_no_komodo_step_without_a_komodo_section(self) -> None:
        plan = plans.compute(self.config, self.request(action="new", service="apps/demo"))
        self.assertNotIn("komodo", [c[0] for c in plan.commands])


class EditTests(PlanTestCase):
    def test_edit_shows_the_change_against_the_current_file(self) -> None:
        self.existing()
        new = COMPOSE.replace("1.27", "1.28")
        plan = plans.compute(self.config, self.request(action="edit", service="apps/demo",
                                                       compose=new))
        self.assertEqual([], plan.blocked)
        self.assertIn("-    image: nginx:1.27", plan.diff)
        self.assertIn("+    image: nginx:1.28", plan.diff)

    def test_nothing_to_change_blocks(self) -> None:
        self.existing()
        plan = plans.compute(self.config, self.request(action="edit", service="apps/demo"))
        self.assertTrue(plan.blocked)

    def test_identical_content_blocks(self) -> None:
        self.existing()
        plan = plans.compute(self.config, self.request(action="edit", service="apps/demo",
                                                       compose=COMPOSE))
        self.assertTrue(any("identical" in b for b in plan.blocked), plan.blocked)

    def test_a_bare_name_is_resolved_and_stored_qualified(self) -> None:
        self.existing()
        plan = plans.compute(self.config, self.request(action="edit", service="demo",
                                                       compose=COMPOSE + "# x\n"))
        self.assertEqual("apps/demo", plan.target)
        self.assertEqual("apps/demo", plan.request.service)

    def test_an_ambiguous_name_blocks(self) -> None:
        self.existing("demo", "apps")
        self.existing("demo", "automation")
        plan = plans.compute(self.config, self.request(action="edit", service="demo",
                                                       compose=COMPOSE + "# x\n"))
        self.assertTrue(any("Ambiguous" in b for b in plan.blocked), plan.blocked)

    def test_a_symlinked_file_is_never_written_through(self) -> None:
        svc = self.existing()
        victim = self.base / "victim.env"
        victim.write_text("SECRET=1", encoding="utf-8")
        (svc / "compose.yaml").unlink()
        (svc / "compose.yaml").symlink_to(victim)
        plan = plans.compute(self.config, self.request(action="edit", service="apps/demo",
                                                       compose=COMPOSE))
        self.assertTrue(any("symlink" in b for b in plan.blocked), plan.blocked)
        self.assertNotIn("SECRET", plan.diff)
        self.assertEqual("SECRET=1", victim.read_text())

    def test_editing_into_a_lint_error_blocks(self) -> None:
        self.existing()
        plan = plans.compute(self.config, self.request(action="edit", service="apps/demo",
                                                       compose=PRIVILEGED))
        self.assertTrue(plan.blocked)


class FixAndRmTests(PlanTestCase):
    def test_nothing_to_fix_blocks(self) -> None:
        self.existing()
        plan = plans.compute(self.config, self.request(action="fix", service="apps/demo"))
        self.assertTrue(any("nothing to fix" in b for b in plan.blocked), plan.blocked)

    def test_a_drifted_mode_is_planned_then_fixed(self) -> None:
        svc = self.existing()
        (svc / "compose.yaml").chmod(0o644)
        plan = plans.save(self.config, plans.compute(
            self.config, self.request(action="fix", service="apps/demo")), origin="test")
        self.assertIn(["chmod", "640", str(svc / "compose.yaml")], plan.commands)
        outcome = plans.apply(self.config, plan.id)
        self.assertTrue(outcome.ok, outcome.failed)
        self.assertEqual(0o640, (svc / "compose.yaml").stat().st_mode & 0o777)

    def test_rm_archives_and_says_the_komodo_stack_stays(self) -> None:
        svc = self.existing()
        plan = plans.save(self.config, plans.compute(
            self.config, self.request(action="rm", service="apps/demo")), origin="test")
        self.assertTrue(any("Komodo" in w for w in plan.warnings))
        outcome = plans.apply(self.config, plan.id)
        self.assertTrue(outcome.ok)
        self.assertFalse(svc.exists())
        self.assertTrue((self.root / ".archive" / "apps" / "demo").is_dir())


class StoreTests(PlanTestCase):
    def _saved_new(self) -> plans.Plan:
        return plans.save(self.config, plans.compute(self.config, self.request(
            action="new", service="apps/demo", compose=COMPOSE, service_yaml=SERVICE)),
            origin="mcp")

    def test_a_saved_plan_has_a_short_id_and_is_root_only(self) -> None:
        plan = self._saved_new()
        self.assertRegex(plan.id, r"^[0-9a-f]{8}$")
        path = self.config.state.plans_dir / f"{plan.id}.json"
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(0o700, self.config.state.plans_dir.stat().st_mode & 0o777)
        self.assertEqual("mcp", plans.load(self.config, plan.id).origin)

    def test_a_blocked_plan_is_never_saved(self) -> None:
        blocked = plans.compute(self.config, self.request(action="new", service="apps/demo",
                                                          compose=PRIVILEGED))
        with self.assertRaises(PlanError):
            plans.save(self.config, blocked, origin="mcp")

    def test_apply_creates_the_service_and_consumes_the_plan(self) -> None:
        plan = self._saved_new()
        outcome = plans.apply(self.config, plan.id)
        self.assertTrue(outcome.ok, outcome.failed)
        self.assertEqual(COMPOSE, (self.root / "apps" / "demo" / "compose.yaml").read_text())
        self.assertEqual([], plans.list_plans(self.config))
        with self.assertRaises(PlanError):
            plans.apply(self.config, plan.id)

    def test_apply_refreshes_the_manifest(self) -> None:
        plans.apply(self.config, self._saved_new().id)
        manifest = json.loads((self.base / "etc" / "manifest.json").read_text())
        self.assertEqual(["demo"], [s["key"] for s in manifest["services"]])

    def test_a_change_between_plan_and_apply_refuses_and_writes_nothing(self) -> None:
        svc = self.existing()
        plan = plans.save(self.config, plans.compute(self.config, self.request(
            action="edit", service="apps/demo", compose=COMPOSE + "# from the plan\n")),
            origin="mcp")
        (svc / "compose.yaml").write_text(COMPOSE + "# edited by hand\n", encoding="utf-8")
        with self.assertRaises(PlanError) as caught:
            plans.apply(self.config, plan.id)
        self.assertIn("changed", str(caught.exception))
        self.assertEqual(COMPOSE + "# edited by hand\n", (svc / "compose.yaml").read_text())
        self.assertEqual([], plans.list_plans(self.config))

    def test_a_plan_that_became_blocked_refuses(self) -> None:
        plan = self._saved_new()
        self.existing()
        with self.assertRaises(PlanError):
            plans.apply(self.config, plan.id)

    def _age(self, plan_id: str, expired_for: timedelta) -> None:
        path = self.config.state.plans_dir / f"{plan_id}.json"
        raw = json.loads(path.read_text())
        raw["expires_at"] = (datetime.now(timezone.utc) - expired_for).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        path.write_text(json.dumps(raw))

    def test_an_expired_plan_refuses(self) -> None:
        plan = self._saved_new()
        self._age(plan.id, timedelta(minutes=1))
        self.assertEqual("expired", plans.list_plans(self.config)[0].status())
        with self.assertRaises(PlanError) as caught:
            plans.apply(self.config, plan.id)
        self.assertIn("expired", str(caught.exception))
        self.assertFalse((self.root / "apps").exists())

    def test_plans_expired_for_a_day_are_purged(self) -> None:
        old, recent = self._saved_new(), self._saved_new()
        self._age(old.id, timedelta(hours=25))
        self._age(recent.id, timedelta(hours=1))
        self.assertEqual([recent.id], [p.id for p in plans.list_plans(self.config)])

    def test_drop_removes_a_pending_plan(self) -> None:
        plan = self._saved_new()
        self.assertEqual(plan.id, plans.drop(self.config, plan.id).id)
        self.assertEqual([], plans.list_plans(self.config))
        with self.assertRaises(PlanError):
            plans.drop(self.config, plan.id)

    def test_a_malformed_id_is_refused_before_touching_the_disk(self) -> None:
        for plan_id in ("../../etc/passwd", "ABCDEF12", "abc", ""):
            with self.assertRaises(PlanError, msg=plan_id):
                plans.load(self.config, plan_id)

    def test_no_plans_directory_means_no_plans(self) -> None:
        self.assertEqual([], plans.list_plans(self.config))

    def test_summary_carries_no_file_contents(self) -> None:
        summary = self._saved_new().summary()
        self.assertNotIn("compose", json.dumps(summary).replace("compose.yaml", ""))
        self.assertEqual("pending", summary["status"])


class KomodoStepTests(PlanTestCase):
    komodo = True

    def test_the_stack_step_is_planned_with_the_service_directory(self) -> None:
        plan = plans.compute(self.config, self.request(action="new", service="apps/demo",
                                                       compose=COMPOSE, stack="demo-stack"))
        self.assertIn(["komodo", "CreateStack", "demo-stack", "/services/apps/demo"],
                      plan.commands)

    def test_apply_creates_the_stack_after_the_files(self) -> None:
        plan = plans.save(self.config, plans.compute(self.config, self.request(
            action="new", service="apps/demo", compose=COMPOSE)), origin="mcp")
        with mock.patch("clixz.plans.komodo_mod.create_stack",
                        return_value="Komodo stack demo created") as create:
            outcome = plans.apply(self.config, plan.id)
        create.assert_called_once()
        self.assertEqual({"name": "demo", "run_directory": "/services/apps/demo"},
                         {k: v for k, v in create.call_args.kwargs.items() if k != "client"})
        self.assertIn("Komodo stack demo created", outcome.notes)

    def test_a_komodo_failure_leaves_the_files_and_warns(self) -> None:
        plan = plans.save(self.config, plans.compute(self.config, self.request(
            action="new", service="apps/demo", compose=COMPOSE)), origin="mcp")
        with mock.patch("clixz.plans.komodo_mod.create_stack",
                        side_effect=KomodoError("Komodo Core unreachable")):
            outcome = plans.apply(self.config, plan.id)
        self.assertTrue(outcome.ok)
        self.assertTrue((self.root / "apps" / "demo" / "compose.yaml").is_file())
        self.assertTrue(any("unreachable" in w for w in outcome.warnings), outcome.warnings)


IGNORE_BASE = (
    "# accepted on this host\n"
    "ignore:\n"
    "  - service: apps/demo\n"
    "    rules: [privileged]\n"
    "    reason: needs the USB stick\n"
)


class IgnorePlanTests(PlanTestCase):
    """ignore.yaml through a plan — never to accept an error-level rule."""

    def setUp(self) -> None:
        super().setUp()
        self.etc = self.base / "etc"
        self.etc.mkdir()
        self.ignore = self.etc / "ignore.yaml"
        self.ignore.write_text(IGNORE_BASE, encoding="utf-8")
        self.ignore.chmod(0o644)
        self.existing("demo")
        self.existing("other")
        self.reload()

    def reload(self) -> None:
        self.config = dataclasses.replace(self.config, config_dir=self.etc,
                                          policy=load_policy(self.etc))

    def plan(self, text: str) -> plans.Plan:
        return plans.compute(self.config, self.request(action="ignore", ignore=text))

    def with_entry(self, service: str, rules: str, reason: str = "looked at") -> str:
        return IGNORE_BASE + (f"  - service: {service}\n    rules: [{rules}]\n"
                              f"    reason: {reason}\n")

    def test_the_request_takes_the_file_and_no_service(self) -> None:
        for raw in ({"action": "ignore"},
                    {"action": "ignore", "ignore": "ignore: []\n", "service": "apps/demo"},
                    {"action": "edit", "service": "apps/demo", "ignore": "ignore: []\n"},
                    {"action": "ignore", "ignore": "x" * (64 * 1024 + 1)}):
            with self.assertRaises(PlanError, msg=repr(raw)):
                Request.from_dict(raw)

    def test_other_requests_keep_their_fingerprint(self) -> None:
        self.assertNotIn("ignore", self.request(action="rm", service="apps/demo").to_dict())

    def test_accepting_a_warning_is_planned_then_applied_with_a_snapshot(self) -> None:
        text = self.with_entry("apps/demo", "image-latest")
        plan = self.plan(text)
        self.assertEqual([], plan.blocked)
        self.assertEqual(str(self.ignore), plan.target)
        self.assertIn("+  - service: apps/demo", plan.diff)
        self.assertIn(["write_file", str(self.ignore)], plan.commands)
        self.assertEqual(IGNORE_BASE, self.ignore.read_text(encoding="utf-8"))  # nothing written

        stored = plans.save(self.config, plan, origin="mcp")
        outcome = plans.apply(self.config, stored.id)
        self.assertTrue(outcome.ok, outcome.failed)
        self.assertEqual(text, self.ignore.read_text(encoding="utf-8"))
        self.assertEqual(0o644, self.ignore.stat().st_mode & 0o777)
        snapshots = list((self.root / ".archive" / "clixz" / "config" / "updates").glob(
            "*-ignore.yaml"))
        self.assertEqual(1, len(snapshots))
        self.assertEqual(IGNORE_BASE, snapshots[0].read_text(encoding="utf-8"))

    def test_accepting_an_error_level_rule_is_blocked(self) -> None:
        plan = self.plan(self.with_entry("apps/other", "privileged"))
        self.assertTrue(plan.blocked)
        self.assertIn("operator", " ".join(plan.blocked))
        self.assertIn("apps/other", " ".join(plan.blocked))
        with self.assertRaises(PlanError):
            plans.save(self.config, plan, origin="mcp")

    def test_widening_an_accepted_error_with_a_glob_is_blocked(self) -> None:
        plan = self.plan(IGNORE_BASE.replace("service: apps/demo", "service: apps/*"))
        self.assertTrue(plan.blocked)

    def test_an_accepted_error_can_be_kept_reworded_or_removed(self) -> None:
        reworded = IGNORE_BASE.replace("needs the USB stick", "flashes ESP boards over USB")
        self.assertEqual([], self.plan(reworded).blocked)
        self.assertEqual([], self.plan(self.with_entry("apps/other", "no-user")).blocked)
        self.assertEqual([], self.plan("ignore: []\n").blocked)

    def test_the_level_comes_from_lint_yaml(self) -> None:
        (self.etc / "lint.yaml").write_text("rules:\n  image-latest: error\n", encoding="utf-8")
        self.reload()
        self.assertTrue(self.plan(self.with_entry("apps/demo", "image-latest")).blocked)

    def test_a_file_with_problems_is_never_written(self) -> None:
        for text in ("ignore: [unclosed\n",
                     "- just a list\n",
                     "ignore:\n  - service: apps/demo\n    rules: [no-user]\n",          # no reason
                     self.with_entry("apps/demo", "no-such-rule"),
                     IGNORE_BASE + "extra: key\n"):
            self.assertTrue(self.plan(text).blocked, text)

    def test_identical_is_blocked(self) -> None:
        self.assertTrue(self.plan(IGNORE_BASE).blocked)

    def test_an_entry_for_no_service_is_a_warning(self) -> None:
        plan = self.plan(self.with_entry("apps/gone", "no-user"))
        self.assertEqual([], plan.blocked)
        self.assertTrue(any("apps/gone" in w for w in plan.warnings), plan.warnings)
        self.assertEqual([], self.plan(self.with_entry("apps/*", "no-user")).warnings)

    def test_a_file_changed_since_the_plan_is_not_overwritten(self) -> None:
        stored = plans.save(self.config, self.plan(self.with_entry("apps/demo", "no-user")),
                            origin="mcp")
        changed = IGNORE_BASE.replace("needs the USB stick", "edited by hand")
        self.ignore.write_text(changed, encoding="utf-8")
        with self.assertRaises(PlanError):
            plans.apply(self.config, stored.id)
        self.assertEqual(changed, self.ignore.read_text(encoding="utf-8"))

    def test_a_symlinked_ignore_yaml_is_refused(self) -> None:
        target = self.base / "elsewhere.yaml"
        target.write_text(IGNORE_BASE, encoding="utf-8")
        self.ignore.unlink()
        self.ignore.symlink_to(target)
        self.assertTrue(self.plan(self.with_entry("apps/demo", "no-user")).blocked)

    def test_a_missing_ignore_yaml_is_created_0644(self) -> None:
        self.ignore.unlink()
        self.reload()
        text = "ignore:\n  - service: apps/demo\n    rules: [no-user]\n    reason: why\n"
        plan = self.plan(text)
        self.assertEqual([], plan.blocked)
        outcome = plans.apply(self.config, plans.save(self.config, plan, origin="mcp").id)
        self.assertTrue(outcome.ok, outcome.failed)
        self.assertEqual(0o644, self.ignore.stat().st_mode & 0o777)

    def test_without_a_config_directory_nothing_is_planned(self) -> None:
        self.config = dataclasses.replace(self.config, config_dir=None)
        self.assertTrue(self.plan("ignore: []\n").blocked)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
