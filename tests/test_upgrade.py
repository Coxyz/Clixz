"""Choosing the upgrade command from the way clixz was installed."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from clixz.daemon import RESTART_MCPD
from clixz.upgrade import (
    RETRIES,
    RETRY_DELAY,
    installed_version,
    latest_version,
    needs_root,
    plan_upgrade,
    run_upgrade,
)


class PlanUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _venv(self, *parts: str, marker: str) -> Path:
        prefix = self.root.joinpath(*parts)
        prefix.mkdir(parents=True)
        (prefix / marker).write_text("", encoding="utf-8")
        return prefix

    def test_global_pipx_install_upgrades_globally(self) -> None:
        prefix = self._venv("pipx", "venvs", "clixz", marker="pipx_metadata.json")
        plan = plan_upgrade(prefix, environ={"PIPX_GLOBAL_HOME": str(self.root / "pipx")})
        self.assertEqual(["pipx", "upgrade", "--pip-args=--no-cache-dir", "--global", "clixz"],
                         plan.argv)
        self.assertEqual({}, plan.env)

    def test_user_pipx_install_stays_a_user_upgrade(self) -> None:
        prefix = self._venv("home", "pipx", "venvs", "clixz", marker="pipx_metadata.json")
        plan = plan_upgrade(prefix, environ={})
        self.assertEqual(["pipx", "upgrade", "--pip-args=--no-cache-dir", "clixz"], plan.argv)

    def test_uv_install_is_pointed_back_at_its_own_directories(self) -> None:
        prefix = self._venv("uv", "tools", "clixz", marker="uv-receipt.toml")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        launcher = bin_dir / "clixz"
        launcher.symlink_to(prefix / "bin" / "clixz")
        plan = plan_upgrade(prefix, launcher, environ={})
        self.assertEqual(["uv", "tool", "upgrade", "--no-cache", "clixz"], plan.argv)
        self.assertEqual({"UV_TOOL_DIR": str(prefix.parent), "UV_TOOL_BIN_DIR": str(bin_dir)},
                         plan.env)

    def test_uv_install_run_without_a_link_leaves_the_bin_dir_alone(self) -> None:
        prefix = self._venv("uv", "tools", "clixz", marker="uv-receipt.toml")
        plan = plan_upgrade(prefix, prefix / "bin" / "clixz", environ={})
        self.assertEqual({"UV_TOOL_DIR": str(prefix.parent)}, plan.env)

    def test_unknown_install_has_no_plan(self) -> None:
        prefix = self.root / "venv"
        prefix.mkdir()
        self.assertIsNone(plan_upgrade(prefix, environ={}))

    def test_a_writable_install_does_not_need_root(self) -> None:
        self.assertFalse(needs_root(self.root))


class AfterUpgradeTests(unittest.TestCase):
    def test_the_version_is_asked_of_a_fresh_interpreter(self) -> None:
        import sys

        import clixz
        # PYTHONPATH reaches the child, so it imports the same source tree.
        self.assertEqual(clixz.__version__, installed_version(sys.executable))

    def test_an_interpreter_that_cannot_answer_is_not_a_crash(self) -> None:
        self.assertIsNone(installed_version("/nonexistent/python"))

    def test_a_stopped_daemon_is_never_started(self) -> None:
        self.assertIn("try-restart", RESTART_MCPD)
        self.assertNotIn("restart", [a for a in RESTART_MCPD if a != "try-restart"])


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class LatestVersionTests(unittest.TestCase):
    def test_the_version_pypi_publishes_is_read_without_cache(self) -> None:
        seen = []

        def opener(request, timeout=None):
            seen.append(request)
            return _Response(json.dumps({"info": {"version": "2.3.0"}}).encode())

        self.assertEqual("2.3.0", latest_version(opener=opener))
        self.assertTrue(seen[0].full_url.endswith("/pypi/clixz/json"))
        self.assertEqual("no-cache", seen[0].get_header("Cache-control"))

    def test_no_answer_is_none_not_a_crash(self) -> None:
        def down(request, timeout=None):
            raise urllib.error.URLError("no network")

        def garbage(request, timeout=None):
            return _Response(b"<html>")

        self.assertIsNone(latest_version(opener=down))
        self.assertIsNone(latest_version(opener=garbage))


class RetryTests(unittest.TestCase):
    def test_the_defaults(self) -> None:
        self.assertEqual((3, 15), (RETRIES, RETRY_DELAY))

    def test_the_installer_is_rerun_until_the_published_version_lands(self) -> None:
        versions = iter(["2.2.3", "2.2.3", "2.3.0"])
        runs, sleeps = [], []
        code, after = run_upgrade(lambda: runs.append(1) or 0, "2.3.0",
                                  version_after=lambda: next(versions), sleep=sleeps.append)
        self.assertEqual((0, "2.3.0"), (code, after))
        self.assertEqual(3, len(runs))
        self.assertEqual([15, 15], sleeps)

    def test_it_gives_up_after_the_last_try(self) -> None:
        runs = []
        code, after = run_upgrade(lambda: runs.append(1) or 0, "2.3.0",
                                  version_after=lambda: "2.2.3", sleep=lambda _: None)
        self.assertEqual((0, "2.2.3"), (code, after))
        self.assertEqual(RETRIES, len(runs))

    def test_a_failing_installer_stops_at_once(self) -> None:
        runs = []
        code, after = run_upgrade(lambda: runs.append(1) or 2, "2.3.0",
                                  version_after=lambda: "2.2.3", sleep=lambda _: None)
        self.assertEqual((2, None), (code, after))
        self.assertEqual(1, len(runs))

    def test_without_pypi_one_run_is_enough(self) -> None:
        runs = []
        code, after = run_upgrade(lambda: runs.append(1) or 0, None,
                                  version_after=lambda: "2.2.3", sleep=lambda _: None)
        self.assertEqual((0, "2.2.3"), (code, after))
        self.assertEqual(1, len(runs))


if __name__ == "__main__":
    unittest.main()
