"""Creating a service tree."""

from __future__ import annotations

import grp
import os
import pwd
import tempfile
import unittest
from pathlib import Path

import yaml

from clixz.config import parse_config
from clixz.scaffold import CreateRequest, create_service, plan_create, validate_service_name


def _owner() -> str:
    return (f"{pwd.getpwuid(os.getuid()).pw_name}:"
            f"{grp.getgrgid(os.getgid()).gr_name}")


def _config(root: Path) -> object:
    user, _, group = _owner().partition(":")
    return parse_config({
        "root_dir": str(root),
        "categories": {"apps": {"user": user, "group": group}},
        "rules": {"dir": {"mode": "750"}, "file": {"mode": "640"},
                  "env": {"mode": "600", "owner": _owner()}},
    })


class NameTests(unittest.TestCase):
    def test_accepts_lowercase_and_hyphens(self) -> None:
        for name in ("api", "home-assistant", "atuin2"):
            validate_service_name(name)

    def test_refuses_anything_that_could_become_a_path(self) -> None:
        for name in ("../etc", "a/b", "-lead", "trail-", "Upper", "with space", ""):
            with self.assertRaises(ValueError, msg=name):
                validate_service_name(name)


class PlanTests(unittest.TestCase):
    def test_plan_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_create(_config(root), CreateRequest("apps", "demo"))
            self.assertFalse((root / "apps").exists())

    def test_plan_lists_the_commands_create_would_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            commands = plan_create(_config(Path(tmp)), CreateRequest("apps", "demo"))
            verbs = {c[0] for c in commands}
            self.assertEqual({"mkdir", "chown", "chmod", "write_file"}, verbs)


class CreateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config = _config(self.root)
        create_service(self.config, CreateRequest("apps", "demo"))
        self.svc = self.root / "apps" / "demo"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_creates_the_whole_skeleton(self) -> None:
        for name in ("config", "data"):
            self.assertTrue((self.svc / name).is_dir(), name)
        for name in ("compose.yaml", "service.yaml", ".env"):
            self.assertTrue((self.svc / name).is_file(), name)

    def test_compose_is_a_usable_template_not_an_empty_file(self) -> None:
        doc = yaml.safe_load((self.svc / "compose.yaml").read_text(encoding="utf-8"))
        self.assertEqual(["demo"], list(doc["services"]))

    def test_modes_follow_the_rules(self) -> None:
        self.assertEqual(0o750, (self.svc / "data").stat().st_mode & 0o777)
        self.assertEqual(0o640, (self.svc / "compose.yaml").stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.svc / ".env").stat().st_mode & 0o777)

    def test_refuses_to_overwrite_an_existing_service(self) -> None:
        with self.assertRaises(RuntimeError):
            create_service(self.config, CreateRequest("apps", "demo"))

    def test_refuses_an_unknown_category(self) -> None:
        with self.assertRaises(KeyError):
            create_service(self.config, CreateRequest("nope", "demo"))
