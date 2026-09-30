"""Choosing the upgrade command from the way clixz was installed."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from clixz.upgrade import needs_root, plan_upgrade


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
        self.assertEqual(["pipx", "upgrade", "--global", "clixz"], plan.argv)
        self.assertEqual({}, plan.env)

    def test_user_pipx_install_stays_a_user_upgrade(self) -> None:
        prefix = self._venv("home", "pipx", "venvs", "clixz", marker="pipx_metadata.json")
        plan = plan_upgrade(prefix, environ={})
        self.assertEqual(["pipx", "upgrade", "clixz"], plan.argv)

    def test_uv_install_is_pointed_back_at_its_own_directories(self) -> None:
        prefix = self._venv("uv", "tools", "clixz", marker="uv-receipt.toml")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        launcher = bin_dir / "clixz"
        launcher.symlink_to(prefix / "bin" / "clixz")
        plan = plan_upgrade(prefix, launcher, environ={})
        self.assertEqual(["uv", "tool", "upgrade", "clixz"], plan.argv)
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


if __name__ == "__main__":
    unittest.main()
