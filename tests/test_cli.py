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


if __name__ == "__main__":
    unittest.main()
