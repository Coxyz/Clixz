"""Tests for service.yaml descriptors and manifest aggregation."""

from __future__ import annotations

import getpass
import grp
import os
import tempfile
from pathlib import Path
import unittest

import yaml

from coxyz.config import CategoryConfig, Config, PrincipalConfig, RuleConfig, SettingsConfig
from coxyz.meta import (
    SERVICE_FILENAME,
    build_manifest,
    parse_meta,
    scaffold_template,
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
            "config_dir": RuleConfig(mode="750"),
            "data_dir": RuleConfig(mode="750", audit_only=True),
            "env_file": RuleConfig(mode="600"),
        },
        exclude=[],
    )


def _write_service(root: Path, service: str, body: str) -> Path:
    svc = root / "apps" / service
    svc.mkdir(parents=True, exist_ok=True)
    (svc / SERVICE_FILENAME).write_text(body, encoding="utf-8")
    return svc


class ParseMetaTests(unittest.TestCase):
    def test_valid_descriptor(self) -> None:
        raw = {
            "name": "Bitwarden", "icon": "🔐",
            "description": "Vault", "public": True,
            "url": "https://vault.coxyz.fr",
            "details": {"summary": "secrets", "ports": ["80 interne"], "depends_on": ["npm"]},
        }
        meta, issues = parse_meta(raw, "apps", "bitwarden")
        self.assertIsNotNone(meta)
        self.assertEqual(issues, [])
        self.assertEqual(meta.kind, "app")          # url present → app
        self.assertEqual(meta.container, "bitwarden")  # defaults to service name
        self.assertEqual(meta.key, "bitwarden")
        self.assertEqual(meta.details["depends_on"], ["npm"])

    def test_missing_required_fields(self) -> None:
        meta, issues = parse_meta({"icon": "x"}, "apps", "demo")
        self.assertIsNone(meta)
        self.assertTrue(any("name" in i for i in issues))
        self.assertTrue(any("description" in i for i in issues))
        self.assertTrue(any("public" in i for i in issues))

    def test_public_must_be_bool(self) -> None:
        meta, issues = parse_meta(
            {"name": "X", "icon": "x", "description": "d", "public": "yes"},
            "apps", "demo",
        )
        self.assertIsNone(meta)
        self.assertTrue(any("public" in i for i in issues))

    def test_kind_defaults_to_infra_without_url(self) -> None:
        meta, _ = parse_meta(
            {"name": "API", "icon": "⚡", "description": "d", "public": True},
            "apps", "api",
        )
        self.assertEqual(meta.kind, "infra")

    def test_invalid_kind_reported(self) -> None:
        _, issues = parse_meta(
            {"name": "X", "icon": "x", "description": "d", "public": True, "kind": "weird"},
            "apps", "demo",
        )
        self.assertTrue(any("kind" in i for i in issues))

    def test_unknown_detail_key_is_soft_warning(self) -> None:
        meta, issues = parse_meta(
            {"name": "X", "icon": "x", "description": "d", "public": True,
             "details": {"bogus": 1, "summary": "ok"}},
            "apps", "demo",
        )
        self.assertIsNotNone(meta)
        self.assertNotIn("bogus", meta.details)
        self.assertTrue(any("bogus" in i for i in issues))


class ScaffoldTemplateTests(unittest.TestCase):
    def test_template_is_valid_yaml_and_private(self) -> None:
        text = scaffold_template("apps", "my-app")
        data = yaml.safe_load(text)
        self.assertEqual(data["public"], False)
        self.assertIn("name", data)
        # A freshly scaffolded descriptor is private but otherwise parseable.
        meta, _ = parse_meta(data, "apps", "my-app")
        self.assertIsNotNone(meta)
        self.assertFalse(meta.public)


class BuildManifestTests(unittest.TestCase):
    def test_aggregates_public_excludes_private_and_sorts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_service(root, "bitwarden", yaml.safe_dump({
                "name": "Bitwarden", "icon": "🔐", "description": "vault",
                "public": True, "url": "https://vault.coxyz.fr",
            }))
            _write_service(root, "api", yaml.safe_dump({
                "name": "API", "icon": "⚡", "description": "rest",
                "public": True, "kind": "infra",
            }))
            _write_service(root, "secret", yaml.safe_dump({
                "name": "Secret", "icon": "🙈", "description": "hidden",
                "public": False,
            }))
            result = build_manifest(_config(root))

            self.assertEqual(result.public_count, 2)
            self.assertEqual(result.private_count, 1)
            self.assertEqual(result.errors, [])
            names = [s["name"] for s in result.manifest["services"]]
            # app kind sorts before infra kind → Bitwarden (app) before API (infra)
            self.assertEqual(names, ["Bitwarden", "API"])
            keys = {s["key"] for s in result.manifest["services"]}
            self.assertNotIn("secret", keys)

    def test_missing_descriptor_is_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "apps" / "nodesc").mkdir(parents=True)
            result = build_manifest(_config(root))
            self.assertEqual(result.public_count, 0)
            self.assertTrue(any("no service.yaml" in w for w in result.warnings))

    def test_invalid_descriptor_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_service(root, "broken", "name: only\n")  # missing required fields
            result = build_manifest(_config(root))
            self.assertTrue(result.errors)
            self.assertEqual(result.public_count, 0)


if __name__ == "__main__":
    unittest.main()
