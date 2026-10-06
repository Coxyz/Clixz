"""The command line end to end, on a temporary tree."""

from __future__ import annotations

import grp
import json
import os
import pwd
import tempfile
import unittest
from pathlib import Path

import yaml

try:
    from typer.testing import CliRunner

    from clixz.cli import app
except ModuleNotFoundError as exc:  # `make test` on a machine without the CLI's dependencies
    raise unittest.SkipTest(f"the command line needs its dependencies: {exc}") from exc

_COMPOSE = """\
services:
  demo:
    image: demo:latest
    privileged: true
    restart: unless-stopped
"""


class CheckSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        me = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        self.config = root / "etc" / "config.yaml"
        self.config.parent.mkdir()
        self.config.write_text(yaml.safe_dump({
            "root_dir": str(root / "tree"),
            "categories": {"apps": {"user": me, "group": group}},
            "rules": {"env": {"mode": "600", "owner": f"{me}:{group}"}},
            "npm": {"database": None},
        }), encoding="utf-8")
        svc = root / "tree" / "apps" / "demo"
        (svc / "config").mkdir(parents=True)
        (svc / "data").mkdir()
        for path, mode in ((svc / "compose.yaml", 0o640), (svc / ".env", 0o600)):
            path.write_text(_COMPOSE if path.suffix == ".yaml" else "", encoding="utf-8")
            path.chmod(mode)
        for path in (root / "tree" / "apps", svc, svc / "config", svc / "data"):
            path.chmod(0o750)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _check(self, *args: str):
        return self.runner.invoke(app, ["-c", str(self.config), "check", *args],
                                  env={"NO_COLOR": "1", "COLUMNS": "200"})

    def test_the_summary_counts_compose_findings_at_every_level(self) -> None:
        summary = json.loads(self._check("--json").stdout)["summary"]
        # service.yaml is missing: the one permission warning.
        self.assertEqual((0, 1), (summary["errors"], summary["warnings"]))
        self.assertEqual(1, summary["lint_errors"])         # privileged
        self.assertEqual(4, summary["lint_warnings"])       # latest, cap_drop, nnp, logging
        self.assertEqual(1, summary["lint_infos"])          # no healthcheck

    def test_the_closing_lines_say_the_same_thing_as_the_list(self) -> None:
        out = self._check().stdout
        self.assertIn("permissions  0 error(s), 1 warning(s)", out)
        self.assertIn("compose      1 error(s), 4 warning(s), 1 info", out)
        self.assertEqual(4, out.count("  warn "))

    def test_an_ignored_finding_leaves_every_count(self) -> None:
        (self.config.parent / "ignore.yaml").write_text(yaml.safe_dump({"ignore": [
            {"service": "apps/demo", "rules": ["privileged", "no-cap-drop", "missing-file"],
             "reason": "test"},
        ]}), encoding="utf-8")
        summary = json.loads(self._check("--json").stdout)["summary"]
        self.assertEqual((0, 0, 3, 3), (summary["warnings"], summary["lint_errors"],
                                        summary["lint_warnings"], summary["ignored"]))


_GOOD = "services:\n  demo:\n    image: nginx:1.27\n    restart: unless-stopped\n"


class ChangeCliTests(unittest.TestCase):
    """new / edit / plan / todo, on a temporary tree and state directory."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        me = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        self.tree = self.base / "tree"
        self.tree.mkdir()
        self.config = self.base / "etc" / "config.yaml"
        self.config.parent.mkdir()
        self.config.write_text(yaml.safe_dump({
            "root_dir": str(self.tree),
            "categories": {"apps": {"user": me, "group": group}},
            "rules": {"env": {"mode": "600", "owner": f"{me}:{group}"}},
            "npm": {"database": None},
            "state": {"dir": str(self.base / "state"), "group": group},
        }), encoding="utf-8")
        self.runner = CliRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def clixz(self, *args: str, stdin: str | None = None):
        env = {"NO_COLOR": "1", "COLUMNS": "200", "CLIXZ_NO_SUDO": "1"}
        return self.runner.invoke(app, ["-c", str(self.config), *args], input=stdin, env=env)

    def write(self, name: str, text: str) -> str:
        path = self.base / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_todo_add_list_and_done(self) -> None:
        added = json.loads(self.clixz("todo", "add", "Backups", "-d", "restic", "--json").stdout)
        self.assertEqual(1, added["id"])
        self.clixz("todo", "add", "Memory limits")
        self.assertEqual(0, self.clixz("todo", "done", "1").exit_code)
        listed = json.loads(self.clixz("todo", "ls", "--json").stdout)
        self.assertEqual(["Memory limits"], [i["title"] for i in listed["items"]])
        everything = json.loads(self.clixz("todo", "ls", "--all", "--json").stdout)
        self.assertEqual(["done", "todo"], [i["state"] for i in everything["items"]])
        shown = json.loads(self.clixz("todo", "show", "1", "--json").stdout)
        self.assertEqual("restic", shown["description"])

    def test_todo_errors_are_messages_not_tracebacks(self) -> None:
        result = self.clixz("todo", "done", "42")
        self.assertEqual(2, result.exit_code)
        self.assertIn("no item #42", result.output)

    def test_new_plan_with_a_privileged_compose_is_blocked(self) -> None:
        compose = self.write("c.yaml", "services:\n  demo:\n    image: x:1\n    privileged: true\n")
        result = self.clixz("new", "apps/demo", "--compose", compose, "--plan", "--json")
        self.assertEqual(1, result.exit_code)
        self.assertTrue(json.loads(result.stdout)["blocked"])
        self.assertFalse((self.tree / "apps").exists())

    def test_new_reads_the_compose_from_stdin(self) -> None:
        result = self.clixz("new", "apps/demo", "--compose", "-", "--yes", stdin=_GOOD)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(_GOOD, (self.tree / "apps" / "demo" / "compose.yaml").read_text())

    def test_edit_plan_shows_a_diff_and_edit_applies_it(self) -> None:
        self.clixz("new", "apps/demo", "--compose", self.write("c.yaml", _GOOD), "--yes")
        changed = self.write("c2.yaml", _GOOD.replace("1.27", "1.28"))
        planned = json.loads(self.clixz("edit", "apps/demo", "--compose", changed,
                                        "--plan", "--json").stdout)
        self.assertIn("+    image: nginx:1.28", planned["diff"])
        self.assertEqual(0, self.clixz("edit", "demo", "--compose", changed, "--yes").exit_code)
        self.assertIn("1.28", (self.tree / "apps" / "demo" / "compose.yaml").read_text())

    def test_plans_prepared_elsewhere_are_listed_shown_applied_and_dropped(self) -> None:
        from clixz import plans
        from clixz.config import load_config

        config, _ = load_config(self.config)
        first = plans.save(config, plans.compute(config, plans.Request(
            action="new", service="apps/demo", compose=_GOOD)), origin="mcp")
        second = plans.save(config, plans.compute(config, plans.Request(
            action="new", service="apps/other", compose=_GOOD)), origin="mcp")
        listed = json.loads(self.clixz("plan", "ls", "--json").stdout)
        self.assertEqual({first.id, second.id}, {p["id"] for p in listed["plans"]})
        shown = json.loads(self.clixz("plan", "show", first.id, "--json").stdout)
        self.assertEqual("apps/demo", shown["target"])
        applied = self.clixz("plan", "apply", first.id, "--yes", "--json")
        self.assertEqual(0, applied.exit_code, applied.output)
        self.assertTrue((self.tree / "apps" / "demo").is_dir())
        self.assertEqual(0, self.clixz("plan", "drop", second.id).exit_code)
        self.assertEqual([], json.loads(self.clixz("plan", "ls", "--json").stdout)["plans"])

    def test_mcp_lists_what_goes_to_clixz_apply(self) -> None:
        payload = json.loads(self.clixz("mcp", "--json").stdout)
        self.assertIn("apply", [r["request"] for r in payload["relay"]])
        self.assertTrue(any("Komodo" in line for line in payload["never"]))



if __name__ == "__main__":
    unittest.main()
