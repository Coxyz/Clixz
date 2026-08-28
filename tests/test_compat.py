"""Tests for the coxyz → clixz compatibility layer.

The rename must not take the running host down: there is a live
/etc/coxyz/config.yaml and systemd units carrying COXYZ_* variables.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from clixz import compat


class EnvFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        for key in ("CLIXZ_TESTVAR", "COXYZ_TESTVAR"):
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        self.env.stop()

    def test_new_name_wins(self) -> None:
        os.environ["COXYZ_TESTVAR"] = "old"
        os.environ["CLIXZ_TESTVAR"] = "new"
        self.assertEqual(compat.env("TESTVAR"), "new")

    def test_falls_back_to_the_legacy_name(self) -> None:
        os.environ["COXYZ_TESTVAR"] = "old"
        self.assertEqual(compat.env("TESTVAR"), "old")

    def test_empty_new_value_does_not_shadow_the_legacy_one(self) -> None:
        # systemd writes `Environment=CLIXZ_X=` for an option left blank; that
        # must not hide a value still set under the old name.
        os.environ["CLIXZ_TESTVAR"] = ""
        os.environ["COXYZ_TESTVAR"] = "old"
        self.assertEqual(compat.env("TESTVAR"), "old")

    def test_default_when_neither_is_set(self) -> None:
        self.assertEqual(compat.env("TESTVAR", "fallback"), "fallback")

    def test_whitespace_is_stripped(self) -> None:
        os.environ["CLIXZ_TESTVAR"] = "  spaced  "
        self.assertEqual(compat.env("TESTVAR"), "spaced")


class ConfigLocationTests(unittest.TestCase):
    def test_new_locations_come_first(self) -> None:
        locations = compat.config_locations()
        clixz_first = next(i for i, p in enumerate(locations) if "clixz" in p.parts)
        coxyz_first = next(i for i, p in enumerate(locations) if "coxyz" in p.parts)
        self.assertLess(clixz_first, coxyz_first)

    def test_legacy_locations_are_still_searched(self) -> None:
        self.assertIn(Path("/etc/coxyz/config.yaml"), compat.config_locations())

    def test_legacy_in_use_is_none_when_a_current_path_exists(self) -> None:
        with mock.patch.object(Path, "is_file", lambda self: "clixz" in self.parts):
            self.assertIsNone(compat.legacy_config_in_use())

    def test_legacy_in_use_reports_the_old_path(self) -> None:
        with mock.patch.object(Path, "is_file", lambda self: "coxyz" in self.parts):
            found = compat.legacy_config_in_use()
        self.assertIsNotNone(found)
        self.assertIn("coxyz", found.parts)


if __name__ == "__main__":
    unittest.main()
