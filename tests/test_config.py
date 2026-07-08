"""Tests for config structural validation (used by `coxyz check`)."""

from __future__ import annotations

import unittest

from coxyz.config import validate_config

_REQUIRED_RULES = ["category_dir", "service_dir", "compose_file", "config_dir", "data_dir", "env_file"]


def _good() -> dict:
    return {
        "root_dir": "/srv/docker",
        "settings": {"principals": {"komodo": {"name": "komodo_runner", "kind": "group"}}},
        "categories": {"apps": {"user": "svc_apps", "group": "svc_apps"}},
        "rules": {r: {"mode": "750"} for r in _REQUIRED_RULES},
    }


class ValidateConfigTests(unittest.TestCase):
    def test_good_config_has_no_issues(self) -> None:
        self.assertEqual([], validate_config(_good()))

    def test_missing_root_dir(self) -> None:
        cfg = _good()
        del cfg["root_dir"]
        self.assertTrue(any("root_dir" in i for i in validate_config(cfg)))

    def test_missing_required_rule_is_reported(self) -> None:
        cfg = _good()
        del cfg["rules"]["env_file"]
        self.assertTrue(any("env_file" in i for i in validate_config(cfg)))

    def test_principal_bad_kind(self) -> None:
        cfg = _good()
        cfg["settings"]["principals"]["komodo"]["kind"] = "nope"
        self.assertTrue(any("kind" in i for i in validate_config(cfg)))

    def test_rule_recursive_must_be_bool(self) -> None:
        cfg = _good()
        cfg["rules"]["config_dir"]["recursive"] = "yes"
        self.assertTrue(any("recursive" in i for i in validate_config(cfg)))

    def test_rule_recursive_bool_is_accepted(self) -> None:
        cfg = _good()
        cfg["rules"]["config_dir"]["recursive"] = True
        self.assertEqual([], validate_config(cfg))

    def test_external_dir_recursive_must_be_bool(self) -> None:
        cfg = _good()
        cfg["images"] = {"dir": "/opt/images", "recursive": "yes"}
        self.assertTrue(any("images.recursive" in i for i in validate_config(cfg)))

    def test_external_dir_dockerfile_recursive_must_be_bool(self) -> None:
        cfg = _good()
        cfg["images"] = {"dir": "/opt/images", "dockerfile": {"mode": "664", "recursive": "yes"}}
        self.assertTrue(
            any("images.dockerfile.recursive" in i for i in validate_config(cfg))
        )

    def test_dev_nested_under_settings_is_flagged(self) -> None:
        # The exact mistake that broke `coxyz dev`: dev indented under settings.
        cfg = _good()
        cfg["settings"]["dev"] = {"principal": "dev"}
        issues = validate_config(cfg)
        self.assertTrue(any("settings.dev" in i for i in issues), issues)

    def test_unknown_top_level_key_is_flagged(self) -> None:
        cfg = _good()
        cfg["compose_template"] = {"default_internal_port": 8080}
        self.assertTrue(any("compose_template" in i for i in validate_config(cfg)))

    def test_dev_principal_unresolvable(self) -> None:
        cfg = _good()
        cfg["dev"] = {"principal": "ghost"}
        self.assertTrue(any("dev.principal" in i for i in validate_config(cfg)))

    def test_dev_principal_resolved_by_name(self) -> None:
        cfg = _good()
        cfg["dev"] = {"principal": "komodo_runner"}  # the principal's name, not key
        self.assertEqual([], validate_config(cfg))


if __name__ == "__main__":
    unittest.main()
