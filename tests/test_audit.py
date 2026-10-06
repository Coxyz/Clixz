"""The audit log: one line per action that changes something."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clixz import audit
from clixz.config import parse_config


def _config(state: Path) -> object:
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CLIXZ_STATE_DIR", None)
        return parse_config({"root_dir": "/srv/docker",
                             "categories": {"apps": {"user": "root", "group": "root"}},
                             "state": {"dir": str(state)}})


class RecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "state"
        self.config = _config(self.state)
        journal = mock.patch.object(audit, "_journal")
        self.journal = journal.start()
        self.addCleanup(journal.stop)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def lines(self) -> list[dict]:
        text = (self.state / "audit.log").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]

    def test_one_json_line_per_action_with_who_what_and_how_it_went(self) -> None:
        audit.record(self.config, "cli", "fix", "apps/demo",
                     commands=[["chmod", "640", "/x"]], actor="alice")
        audit.record(self.config, "mcp", "apply", "apps/demo", ok=False, plan_id="0a1b2c3d",
                     error="changed since the plan")
        first, second = self.lines()
        self.assertEqual({"time", "source", "actor", "action", "target", "ok", "plan_id",
                          "commands", "error", "notes"}, set(first))
        self.assertEqual(("cli", "alice", "fix", "apps/demo", True),
                         (first["source"], first["actor"], first["action"], first["target"],
                          first["ok"]))
        self.assertEqual([["chmod", "640", "/x"]], first["commands"])
        self.assertEqual(("mcp", False, "0a1b2c3d"), (second["actor"], second["ok"],
                                                     second["plan_id"]))
        self.assertRegex(first["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_the_journal_gets_a_copy(self) -> None:
        audit.record(self.config, "cli", "rm", "apps/demo", actor="alice")
        message = self.journal.call_args.args[0]
        for part in ("cli", "alice", "rm", "apps/demo", "ok"):
            self.assertIn(part, message)

    def test_behind_sudo_the_actor_is_the_person(self) -> None:
        with mock.patch.object(os, "geteuid", return_value=0), \
                mock.patch.dict(os.environ, {"SUDO_USER": "opxyz"}):
            self.assertEqual("opxyz", audit.current_actor())

    def test_through_the_mcp_the_actor_is_mcp(self) -> None:
        audit.record(self.config, "mcp", "todo add", "#1")
        self.assertEqual("mcp", self.lines()[0]["actor"])

    def test_the_file_is_readable_by_everyone(self) -> None:
        audit.record(self.config, "cli", "fix", "apps/demo")
        self.assertEqual(0o664, (self.state / "audit.log").stat().st_mode & 0o777)

    def test_a_long_command_list_is_capped(self) -> None:
        audit.record(self.config, "cli", "fix", "all services",
                     commands=[["chmod", "640", f"/x{i}"] for i in range(500)])
        entry = self.lines()[0]
        self.assertEqual(audit.MAX_COMMANDS, len(entry["commands"]))
        self.assertEqual(500, entry["commands_total"])

    def test_the_log_rotates_past_its_size(self) -> None:
        with mock.patch.object(audit, "MAX_BYTES", 300):
            for i in range(10):
                audit.record(self.config, "cli", "todo add", f"#{i}")
        self.assertTrue((self.state / "audit.log.1").is_file())
        self.assertLess((self.state / "audit.log").stat().st_size, 600)

    def test_logging_never_breaks_the_action(self) -> None:
        (self.state).mkdir(parents=True)
        (self.state / "audit.log").mkdir()  # cannot be opened as a file
        audit.record(self.config, "cli", "fix", "apps/demo")  # must not raise


class ReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name)
        self.config = _config(self.state)
        with mock.patch.object(audit, "_journal"):
            for action, target in (("new", "apps/a"), ("fix", "apps/a"), ("rm", "apps/b")):
                audit.record(self.config, "cli", action, target, actor="alice")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_newest_first(self) -> None:
        self.assertEqual(["rm", "fix", "new"], [e["action"] for e in audit.entries(self.config)])

    def test_limit_and_filters(self) -> None:
        self.assertEqual(["rm"], [e["action"] for e in audit.entries(self.config, limit=1)])
        self.assertEqual(["fix", "new"],
                         [e["action"] for e in audit.entries(self.config, target="apps/a")])
        self.assertEqual(["fix"], [e["action"] for e in audit.entries(self.config, action="fix")])

    def test_a_corrupt_line_is_skipped(self) -> None:
        with (self.state / "audit.log").open("a", encoding="utf-8") as f:
            f.write("{not json\n")
        self.assertEqual(3, len(audit.entries(self.config)))

    def test_the_rotated_file_is_read_too(self) -> None:
        (self.state / "audit.log").rename(self.state / "audit.log.1")
        with mock.patch.object(audit, "_journal"):
            audit.record(self.config, "cli", "edit", "apps/a", actor="alice")
        self.assertEqual(["edit", "rm", "fix", "new"],
                         [e["action"] for e in audit.entries(self.config)])

    def test_no_log_yet_is_an_empty_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual([], audit.entries(_config(Path(tmp) / "nothing")))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
