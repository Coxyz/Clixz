"""Tests for the image module, external-dir config and audit."""

from __future__ import annotations

import getpass
import grp
import os
import tempfile
import unittest
from pathlib import Path

import yaml

from clixz.config import (
    CategoryConfig,
    Config,
    ExternalDirConfig,
    PrincipalConfig,
    RuleConfig,
    SettingsConfig,
    _parse_config,
)
from clixz.image import dockerfile_template, validate_image_name
from clixz.policy import Severity, apply_findings, audit_external_dir


def _self_user() -> str:
    return getpass.getuser()


def _self_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def _config(root: Path) -> Config:
    return Config(
        root_dir=root,
        settings=SettingsConfig(principals={"komodo": PrincipalConfig(name="root", kind="group")}),
        categories={"apps": CategoryConfig(user=_self_user(), group=_self_group())},
        rules={k: RuleConfig(mode="750") for k in
               ("category_dir", "service_dir", "compose_file", "config_dir", "data_dir", "env_file")},
        exclude=[],
    )


class ImageNameTests(unittest.TestCase):
    def test_valid_names(self) -> None:
        for name in ("api", "api-clixz", "my_img", "img.1", "a1"):
            validate_image_name(name)  # must not raise

    def test_invalid_names(self) -> None:
        for name in ("", "-api", "api-", ".api", "a/b", "a b"):
            with self.assertRaises(ValueError):
                validate_image_name(name)


class DockerfileTemplateTests(unittest.TestCase):
    def test_template_mentions_context_and_from(self) -> None:
        text = dockerfile_template("api")
        self.assertIn("FROM", text)
        self.assertIn("/opt/images/api", text)


class ExternalDirConfigParsingTests(unittest.TestCase):
    BASE = {
        "root_dir": "/srv/docker",
        "settings": {"principals": {"komodo": {"name": "boxyz_komodo", "kind": "group"}}},
        "categories": {"apps": {"user": "svc_apps", "group": "svc_apps"}},
        "rules": {
            "category_dir": {"mode": "750"}, "service_dir": {"mode": "750"},
            "compose_file": {"mode": "660"}, "config_dir": {"mode": "750"},
            "data_dir": {"mode": "750"}, "env_file": {"mode": "600"},
        },
    }

    def test_defaults_when_absent(self) -> None:
        cfg = _parse_config(dict(self.BASE))
        self.assertEqual(cfg.images.dir, Path("/opt/images"))
        self.assertEqual(cfg.repos.dir, Path("/opt/repos"))
        self.assertEqual(cfg.images.owner, "boxyz_dev:boxyz_dev")
        self.assertEqual(cfg.images.mode, "775")

    def test_overrides(self) -> None:
        raw = dict(self.BASE)
        raw["images"] = {"dir": "/data/images", "owner": "build:build", "mode": "750"}
        raw["repos"] = {"dir": "/data/repos"}
        cfg = _parse_config(raw)
        self.assertEqual(cfg.images.dir, Path("/data/images"))
        self.assertEqual(cfg.images.owner, "build:build")
        self.assertEqual(cfg.images.mode, "750")
        self.assertEqual(cfg.repos.dir, Path("/data/repos"))
        self.assertEqual(cfg.repos.owner, "boxyz_dev:boxyz_dev")  # default

    def test_acl_parsed(self) -> None:
        raw = dict(self.BASE)
        raw["images"] = {"dir": "/opt/images", "acl": {"komodo": "rx"}}
        cfg = _parse_config(raw)
        self.assertEqual(cfg.images.acl, {"komodo": "rx"})
        self.assertIsNone(cfg.repos.acl)  # absent -> None

    def test_acl_unknown_principal_raises(self) -> None:
        raw = dict(self.BASE)
        raw["repos"] = {"dir": "/opt/repos", "acl": {"nope": "rx"}}
        with self.assertRaises(ValueError):
            _parse_config(raw)

    def test_dockerfile_rule_parsed(self) -> None:
        raw = dict(self.BASE)
        raw["images"] = {
            "dir": "/opt/images",
            "dockerfile": {"mode": "664", "acl": {"komodo": "r"}},
        }
        cfg = _parse_config(raw)
        self.assertIsNotNone(cfg.images.dockerfile)
        self.assertEqual(cfg.images.dockerfile.mode, "664")
        self.assertEqual(cfg.images.dockerfile.acl, {"komodo": "r"})
        self.assertIsNone(cfg.repos.dockerfile)  # absent -> None

    def test_dockerfile_acl_unknown_principal_raises(self) -> None:
        raw = dict(self.BASE)
        raw["images"] = {"dir": "/opt/images", "dockerfile": {"acl": {"nope": "r"}}}
        with self.assertRaises(ValueError):
            _parse_config(raw)


class AuditExternalDirTests(unittest.TestCase):
    def test_acl_drift_plans_setfacl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            images = root / "images"
            (images / "myimg").mkdir(parents=True)

            ext = ExternalDirConfig(
                dir=images, owner=f"{_self_user()}:{_self_group()}", mode="775",
                acl={"komodo": "rx"},
            )
            findings = audit_external_dir(
                _config(root), ext, "image_dir",
                acl_enabled=True, principals_available={"komodo": True},
            )
            self.assertEqual(len(findings), 1)
            self.assertIs(findings[0].severity, Severity.DRIFT)
            self.assertTrue(any("acl entry" in i for i in findings[0].issues))
            self.assertTrue(
                any(cmd and cmd[0] == "setfacl" for cmd in findings[0].fixes)
            )

    def test_dockerfile_audited_only_with_file_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            images = root / "images"
            (images / "myimg").mkdir(parents=True)
            (images / "myimg" / "Dockerfile").write_text("FROM scratch\n")

            ext = ExternalDirConfig(
                dir=images, owner=f"{_self_user()}:{_self_group()}", mode="775",
                dockerfile=RuleConfig(mode="664", acl={"komodo": "r"}),
            )
            cfg = _config(root)

            # Without file_name: the Dockerfile is left alone (one finding: the dir).
            dir_only = audit_external_dir(
                cfg, ext, "image_dir",
                acl_enabled=True, principals_available={"komodo": True},
            )
            self.assertEqual(len(dir_only), 1)

            # With file_name: the Dockerfile is audited and its ACL drift planned.
            withf = audit_external_dir(
                cfg, ext, "image_dir",
                acl_enabled=True, principals_available={"komodo": True},
                file_name="Dockerfile",
            )
            df = [f for f in withf if f.path.name == "Dockerfile"]
            self.assertEqual(len(df), 1)
            self.assertIs(df[0].severity, Severity.DRIFT)
            self.assertTrue(any(cmd and cmd[0] == "setfacl" for cmd in df[0].fixes))

    def test_detects_and_fixes_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            images = root / "images"
            (images / "myimg").mkdir(parents=True)
            os.chmod(images / "myimg", 0o700)  # wrong; expect 775

            ext = ExternalDirConfig(
                dir=images, owner=f"{_self_user()}:{_self_group()}", mode="775",
            )
            findings = audit_external_dir(
                _config(root), ext, "image_dir",
                acl_enabled=False, principals_available={},
            )
            self.assertEqual(len(findings), 1)
            self.assertIs(findings[0].severity, Severity.DRIFT)
            self.assertTrue(any("mode" in i for i in findings[0].issues))

            apply_findings(findings, dry_run=False)
            after = audit_external_dir(
                _config(root), ext, "image_dir",
                acl_enabled=False, principals_available={},
            )
            self.assertTrue(all(f.severity is Severity.OK for f in after))

    def test_empty_or_missing_dir_yields_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ext = ExternalDirConfig(dir=Path(tmp) / "nope", owner="root:root", mode="775")
            self.assertEqual(
                audit_external_dir(_config(Path(tmp)), ext, "image_dir",
                                   acl_enabled=False, principals_available={}),
                [],
            )


if __name__ == "__main__":
    unittest.main()
