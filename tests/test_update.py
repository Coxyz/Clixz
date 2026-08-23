"""Tests for `update`: only compose.yaml and service.yaml, always validated."""

from __future__ import annotations

import getpass
import grp
import os
import tempfile
import unittest
from pathlib import Path

from coxyz.config import CategoryConfig, Config, PrincipalConfig, RuleConfig, SettingsConfig
from coxyz.update import (
    PROTECTED,
    UPDATABLE,
    UpdateRequest,
    update_service,
    validate_content,
    validate_target,
)


def _self_user() -> str:
    return getpass.getuser()


def _self_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def _config(root: Path) -> Config:
    return Config(
        root_dir=root,
        settings=SettingsConfig(principals={"komodo": PrincipalConfig(name="root", kind="group")}),
        categories={"apps": CategoryConfig(user=_self_user(), group=_self_group())},
        rules={
            "category_dir": RuleConfig(mode="750"),
            "service_dir": RuleConfig(mode="750"),
            "compose_file": RuleConfig(mode="660"),
            "service_file": RuleConfig(mode="640"),
            "config_dir": RuleConfig(mode="750"),
            "data_dir": RuleConfig(mode="750", audit_only=True),
            "env_file": RuleConfig(mode="600"),
        },
        exclude=[],
    )


def _service(root: Path) -> Path:
    svc = root / "apps" / "demo"
    (svc / "config").mkdir(parents=True)
    (svc / "data").mkdir()
    (svc / "compose.yaml").write_text("services:\n  demo:\n    image: nginx\n", encoding="utf-8")
    (svc / ".env").write_text("SECRET=hunter2\n", encoding="utf-8")
    return svc


VALID_DESCRIPTOR = (
    'name: "Demo"\n'
    'icon: "🧪"\n'
    'description: "A demo service."\n'
    "public: false\n"
    "kind: app\n"
    "container: demo\n"
)


class TargetGuardTests(unittest.TestCase):
    def test_only_compose_and_service_are_updatable(self) -> None:
        self.assertEqual(set(UPDATABLE), {"compose", "service"})

    def test_rejects_env_config_and_data(self) -> None:
        for target in ("env", ".env", "config", "data", "config/", "../../etc/passwd"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    validate_target(target)

    def test_error_message_names_the_protected_paths(self) -> None:
        with self.assertRaises(ValueError) as cm:
            validate_target("env")
        for protected in PROTECTED:
            self.assertIn(protected, str(cm.exception))


class ContentValidationTests(unittest.TestCase):
    def test_rejects_invalid_yaml(self) -> None:
        with self.assertRaises(ValueError):
            validate_content("apps", "demo", "compose", "services:\n  a: [unclosed\n")

    def test_rejects_compose_without_services(self) -> None:
        with self.assertRaises(ValueError):
            validate_content("apps", "demo", "compose", 'version: "3"\n')

    def test_rejects_non_mapping(self) -> None:
        with self.assertRaises(ValueError):
            validate_content("apps", "demo", "compose", "- a\n- b\n")

    def test_rejects_invalid_descriptor(self) -> None:
        with self.assertRaises(ValueError):
            validate_content("apps", "demo", "service", 'name: ""\n')

    def test_accepts_valid_descriptor(self) -> None:
        self.assertIsInstance(
            validate_content("apps", "demo", "service", VALID_DESCRIPTOR), list
        )


class UpdateServiceTests(unittest.TestCase):
    def test_writes_compose_and_snapshots_the_previous_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            svc = _service(root)
            cfg = _config(root)
            new = "services:\n  demo:\n    image: nginx:1.27\n"
            result = update_service(
                cfg,
                UpdateRequest("apps", "demo", "compose", new),
                dry_run=False, acl_enabled=False, principals_available={},
            )
            self.assertEqual((svc / "compose.yaml").read_text(encoding="utf-8"), new)
            self.assertIsNotNone(result.snapshot)
            self.assertTrue(result.snapshot.is_file())
            self.assertIn("nginx\n", result.snapshot.read_text(encoding="utf-8"))

    def test_never_touches_env_config_or_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            svc = _service(root)
            cfg = _config(root)
            update_service(
                cfg,
                UpdateRequest("apps", "demo", "compose", "services:\n  demo:\n    image: a\n"),
                dry_run=False, acl_enabled=False, principals_available={},
            )
            self.assertEqual((svc / ".env").read_text(encoding="utf-8"), "SECRET=hunter2\n")
            self.assertTrue((svc / "config").is_dir())
            self.assertTrue((svc / "data").is_dir())

    def test_identical_content_is_a_no_op(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _service(root)
            cfg = _config(root)
            same = "services:\n  demo:\n    image: nginx\n"
            result = update_service(
                cfg,
                UpdateRequest("apps", "demo", "compose", same),
                dry_run=False, acl_enabled=False, principals_available={},
            )
            self.assertTrue(result.unchanged)
            self.assertIsNone(result.snapshot)

    def test_rejects_empty_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _service(root)
            with self.assertRaises(ValueError):
                update_service(
                    _config(root),
                    UpdateRequest("apps", "demo", "compose", "   \n"),
                    dry_run=True, acl_enabled=False, principals_available={},
                )

    def test_rejects_unknown_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _service(root)
            with self.assertRaises(RuntimeError):
                update_service(
                    _config(root),
                    UpdateRequest("apps", "ghost", "compose", "services:\n  a:\n    image: b\n"),
                    dry_run=True, acl_enabled=False, principals_available={},
                )

    def test_refuses_a_symlinked_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            svc = _service(root)
            outside = root / "outside.yaml"
            outside.write_text("services:\n  x:\n    image: a\n", encoding="utf-8")
            (svc / "compose.yaml").unlink()
            (svc / "compose.yaml").symlink_to(outside)
            with self.assertRaises(RuntimeError):
                update_service(
                    _config(root),
                    UpdateRequest("apps", "demo", "compose", "services:\n  y:\n    image: c\n"),
                    dry_run=True, acl_enabled=False, principals_available={},
                )
            self.assertIn("image: a", outside.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
