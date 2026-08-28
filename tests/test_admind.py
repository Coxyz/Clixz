"""Tests for the privileged daemon's protocol.

These assert the security properties the daemon exists for: no delete opcode,
protected services out of reach, and an apply that is cryptographically bound to
the plan a human reviewed.
"""

from __future__ import annotations

import getpass
import grp
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clixz import admind
from clixz.config import CategoryConfig, Config, PrincipalConfig, RuleConfig, SettingsConfig
from clixz.spec import SPEC_FILENAME, SpecError


def _config(root: Path) -> Config:
    return Config(
        root_dir=root,
        settings=SettingsConfig(principals={}),
        categories={
            c: CategoryConfig(user=getpass.getuser(), group=grp.getgrgid(os.getgid()).gr_name)
            for c in ("apps", "infra", "network")
        },
        rules={k: RuleConfig(mode=m) for k, m in [
            ("category_dir", "750"), ("service_dir", "750"), ("compose_file", "640"),
            ("service_file", "640"), ("spec_file", "640"), ("config_dir", "750"),
            ("data_dir", "750"), ("env_file", "600"),
        ]},
        exclude=[],
    )


SPEC = {"category": "apps", "service": "demo", "image": "nginx:1.27.3", "expose": ["8080"]}


class DaemonTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = _config(self.root)
        self.ctx = mock.patch.object(
            admind, "_ctx", lambda: (self.cfg, False, {})
        )
        self.ctx.start()
        self.audit = mock.patch.object(admind, "_audit", lambda *a, **k: None)
        self.audit.start()
        admind.PLANS = admind.PlanStore()

    def tearDown(self) -> None:
        self.ctx.stop()
        self.audit.stop()
        self.tmp.cleanup()

    def _service(self, category: str = "apps", service: str = "demo") -> Path:
        from clixz.spec import render_compose, spec_from_dict, spec_json, validate

        svc = self.root / category / service
        (svc / "data").mkdir(parents=True)
        spec = validate(spec_from_dict({**SPEC, "category": category, "service": service}), self.cfg)
        (svc / "compose.yaml").write_text(render_compose(spec, self.cfg), encoding="utf-8")
        (svc / SPEC_FILENAME).write_text(spec_json(spec), encoding="utf-8")
        (svc / ".env").write_text("SECRET=hunter2\n", encoding="utf-8")
        return svc


class OpcodeTests(DaemonTestCase):
    def test_there_is_no_delete_opcode(self) -> None:
        # Deletion is not refused, it is unreachable: nothing maps to it.
        self.assertNotIn("delete", admind._PLAN_OPS)
        self.assertNotIn("remove", admind._PLAN_OPS)
        for action in ("delete", "remove", "destroy", "force"):
            with self.subTest(action=action):
                with self.assertRaises(admind.AdminError):
                    admind.handle({"op": "plan", "action": action})

    def test_rejects_unknown_op(self) -> None:
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "exec", "cmd": "sh"})

    def test_rejects_non_object(self) -> None:
        for payload in ("string", ["a"], 42, None):
            with self.subTest(payload=payload):
                with self.assertRaises(admind.AdminError):
                    admind.handle(payload)


class ProtectedTargetTests(DaemonTestCase):
    def test_protected_services_cannot_be_planned(self) -> None:
        for category, service in (("apps", "mcp"), ("network", "npm")):
            self._service(category, service)
            with self.subTest(target=f"{category}/{service}"):
                with self.assertRaises(admind.AdminError):
                    admind.handle({"op": "plan", "action": "update",
                                   "service": f"{category}/{service}",
                                   "patch": {"mem_limit": "1g"}})

    def test_the_whole_infra_category_is_protected(self) -> None:
        self._service("infra", "komodo")
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "plan", "action": "archive", "service": "infra/komodo"})

    def test_protected_create_is_refused(self) -> None:
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "plan", "action": "create",
                           "spec": {**SPEC, "service": "mcp"}})


class PlanBindingTests(DaemonTestCase):
    def test_apply_requires_the_plan_hash(self) -> None:
        self._service()
        plan = admind.handle({"op": "plan", "action": "update", "service": "demo",
                              "patch": {"mem_limit": "1g"}})
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": "0" * 64})

    def test_a_plan_is_single_use(self) -> None:
        self._service()
        plan = admind.handle({"op": "plan", "action": "update", "service": "demo",
                              "patch": {"mem_limit": "1g"}})
        admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": plan["hash"]})
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": plan["hash"]})

    def test_a_wrong_hash_does_not_destroy_the_plan(self) -> None:
        # A truncated or mistyped hash is a client glitch, not an attack: it
        # must not cost the user their approved plan.
        self._service()
        plan = admind.handle({"op": "plan", "action": "update", "service": "demo",
                              "patch": {"mem_limit": "1g"}})
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": "0" * 64})
        result = admind.handle({"op": "apply", "plan_id": plan["plan_id"],
                                "hash": plan["hash"]})
        self.assertTrue(result["applied"])

    def test_repeated_wrong_hashes_discard_the_plan(self) -> None:
        self._service()
        plan = admind.handle({"op": "plan", "action": "update", "service": "demo",
                              "patch": {"mem_limit": "1g"}})
        for _ in range(admind.MAX_HASH_ATTEMPTS):
            with self.assertRaises(admind.AdminError):
                admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": "0" * 64})
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": plan["hash"]})

    def test_unknown_plan_is_refused(self) -> None:
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "apply", "plan_id": "nope", "hash": "0" * 64})

    def test_expired_plan_is_refused(self) -> None:
        self._service()
        plan = admind.handle({"op": "plan", "action": "update", "service": "demo",
                              "patch": {"mem_limit": "1g"}})
        with mock.patch.object(admind.time, "monotonic", lambda: 10 ** 9):
            with self.assertRaises(admind.AdminError):
                admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": plan["hash"]})

    def test_plan_does_not_write_anything(self) -> None:
        svc = self._service()
        before = (svc / "compose.yaml").read_text(encoding="utf-8")
        admind.handle({"op": "plan", "action": "update", "service": "demo",
                       "patch": {"mem_limit": "2g"}})
        self.assertEqual((svc / "compose.yaml").read_text(encoding="utf-8"), before)


class ApplyTests(DaemonTestCase):
    def test_update_rewrites_compose_and_spec(self) -> None:
        import yaml

        svc = self._service()
        plan = admind.handle({"op": "plan", "action": "update", "service": "demo",
                              "patch": {"mem_limit": "1g"}})
        result = admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": plan["hash"]})

        self.assertTrue(result["applied"])
        doc = yaml.safe_load((svc / "compose.yaml").read_text(encoding="utf-8"))
        self.assertEqual(doc["services"]["demo"]["mem_limit"], "1g")
        self.assertIn('"mem_limit": "1g"', (svc / SPEC_FILENAME).read_text(encoding="utf-8"))
        self.assertIsNotNone(result["snapshot"])

    def test_update_never_touches_secrets_or_state(self) -> None:
        svc = self._service()
        plan = admind.handle({"op": "plan", "action": "update", "service": "demo",
                              "patch": {"mem_limit": "1g"}})
        admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": plan["hash"]})
        self.assertEqual((svc / ".env").read_text(encoding="utf-8"), "SECRET=hunter2\n")
        self.assertTrue((svc / "data").is_dir())

    def test_archive_moves_the_tree(self) -> None:
        svc = self._service()
        plan = admind.handle({"op": "plan", "action": "archive", "service": "demo"})
        result = admind.handle({"op": "apply", "plan_id": plan["plan_id"], "hash": plan["hash"]})
        self.assertFalse(svc.exists())
        self.assertTrue(Path(result["archived_to"]).is_dir())

    def test_create_refuses_an_existing_service(self) -> None:
        self._service()
        with self.assertRaises(admind.AdminError):
            admind.handle({"op": "plan", "action": "create", "spec": SPEC})

    def test_update_needs_a_stored_spec(self) -> None:
        svc = self.root / "apps" / "legacy"
        svc.mkdir(parents=True)
        (svc / "compose.yaml").write_text("services:\n  legacy:\n    image: a:1\n", encoding="utf-8")
        with self.assertRaises(SpecError):
            admind.handle({"op": "plan", "action": "update", "service": "legacy",
                           "patch": {"mem_limit": "1g"}})

    def test_hostile_patch_is_refused(self) -> None:
        self._service()
        with self.assertRaises(SpecError):
            admind.handle({"op": "plan", "action": "update", "service": "demo",
                           "patch": {"privileged": True}})


if __name__ == "__main__":
    unittest.main()
