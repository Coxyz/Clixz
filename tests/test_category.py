"""`clixz category add`: the plan, and the text edit of config.yaml."""

from __future__ import annotations

import grp
import os
import pwd
import tempfile
import unittest
from pathlib import Path

import yaml

from clixz.category import default_account, insert_category, plan_add
from clixz.config import load_config

_BLOCK = """\
# comment worth keeping
root_dir: /srv/docker

categories:
  apps:
    user: svc_apps
    group: svc_apps
  infra:
    user: svc_infra
    group: svc_infra

rules:
  dir: { mode: "750" }
"""

_FLOW = """\
root_dir: /srv/docker
categories:
  apps:        { user: svc_apps,        group: svc_apps }
  # monitoring is next
  monitoring:  { user: svc_monitoring,  group: svc_monitoring }
exclude: []
"""


class InsertTests(unittest.TestCase):
    def test_the_entry_lands_in_the_block_and_comments_survive(self) -> None:
        for text in (_BLOCK, _FLOW):
            out = insert_category(text, "media", "svc_media", "svc_media")
            parsed = yaml.safe_load(out)
            self.assertEqual({"user": "svc_media", "group": "svc_media"},
                             parsed["categories"]["media"])
            self.assertEqual(len(yaml.safe_load(text)["categories"]) + 1,
                             len(parsed["categories"]))
            self.assertEqual(yaml.safe_load(text).get("rules"), parsed.get("rules"))
            self.assertEqual(text.count("#"), out.count("#"))

    def test_a_config_without_a_categories_block_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            insert_category("root_dir: /x\ncategories: {a: {user: u, group: g}}\n",
                            "media", "u", "g")


class PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.me = pwd.getpwuid(os.getuid()).pw_name
        self.source = self.dir / "config.yaml"
        self.source.write_text(
            f"root_dir: {self.dir / 'tree'}\n"
            "categories:\n"
            f"  apps: {{ user: {self.me}, group: {grp.getgrgid(os.getgid()).gr_name} }}\n",
            encoding="utf-8")
        self.config, _ = load_config(self.source)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_new_account_is_created_before_the_directory_it_owns(self) -> None:
        plan = plan_add(self.config, self.source, "media", "svc_clixz_test_absent")
        verbs = [c[0] for c in plan.commands]
        self.assertEqual(["groupadd", "useradd", "mkdir", "chown", "chmod", "write_file"], verbs)
        self.assertIn(str(self.dir / "tree" / "media"), plan.commands[2])
        self.assertEqual(2, len(plan.notes))

    def test_an_existing_account_is_reused(self) -> None:
        plan = plan_add(self.config, self.source, "media", "root")
        self.assertNotIn("useradd", [c[0] for c in plan.commands])
        self.assertNotIn("groupadd", [c[0] for c in plan.commands])

    def test_planning_writes_nothing(self) -> None:
        before = self.source.read_text(encoding="utf-8")
        plan_add(self.config, self.source, "media", "root")
        self.assertEqual(before, self.source.read_text(encoding="utf-8"))
        self.assertFalse((self.dir / "tree" / "media").exists())

    def test_refusals(self) -> None:
        for name in ("apps", "Media", "../x", ".archive", "a/b", "-x"):
            with self.assertRaises(ValueError, msg=name):
                plan_add(self.config, self.source, name, "root")
        with self.assertRaises(ValueError):
            plan_add(self.config, None, "media", "root")

    def test_the_default_account_follows_the_name(self) -> None:
        self.assertEqual("svc_home_lab", default_account("home-lab"))


if __name__ == "__main__":
    unittest.main()
