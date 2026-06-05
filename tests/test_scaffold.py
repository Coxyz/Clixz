"""Tests for `create` scaffolding: structure only, no compose templating."""

from __future__ import annotations

import getpass
import grp
import os
import tempfile
import unittest
from pathlib import Path

from coxyz.config import CategoryConfig, Config, PrincipalConfig, RuleConfig, SettingsConfig
from coxyz.scaffold import CreateRequest, create_service, validate_service_name


def _self_user() -> str:
    return getpass.getuser()


def _self_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def _config(root: Path) -> Config:
    # env_file is owned by the test user (not root:root) so chown works unprivileged.
    return Config(
        root_dir=root,
        settings=SettingsConfig(principals={"komodo": PrincipalConfig(name="root", kind="group")}),
        categories={"apps": CategoryConfig(user=_self_user(), group=_self_group())},
        rules={
            "category_dir": RuleConfig(mode="750"),
            "service_dir": RuleConfig(mode="750"),
            "compose_file": RuleConfig(mode="660"),
            "config_dir": RuleConfig(mode="750"),
            "data_dir": RuleConfig(mode="750", audit_only=True),
            "env_file": RuleConfig(mode="600"),
        },
        exclude=[],
    )


class CreateServiceTests(unittest.TestCase):
    def test_lays_out_dirs_and_empty_compose_and_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_service(
                _config(root), CreateRequest(category="apps", service="demo"),
                dry_run=False, acl_enabled=False, principals_available={},
            )
            svc = root / "apps" / "demo"
            self.assertTrue((svc / "config").is_dir())
            self.assertTrue((svc / "data").is_dir())
            compose = svc / "compose.yaml"
            env = svc / ".env"
            self.assertTrue(compose.is_file())
            self.assertTrue(env.is_file())
            # Created empty — `create` no longer templates compose.yaml.
            self.assertEqual("", compose.read_text())
            self.assertEqual("", env.read_text())

    def test_existing_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "apps" / "demo").mkdir(parents=True)
            with self.assertRaises(RuntimeError):
                create_service(
                    _config(root), CreateRequest(category="apps", service="demo"),
                    dry_run=True, acl_enabled=False, principals_available={},
                )

    def test_invalid_service_name(self) -> None:
        with self.assertRaises(ValueError):
            validate_service_name("-nope")


if __name__ == "__main__":
    unittest.main()
