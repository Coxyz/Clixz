"""Service descriptors and the manifest they feed."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from clixz.config import parse_config
from clixz.meta import build_manifest, declared_urls, parse_meta, scaffold_template, write_manifest


def _config(root: Path) -> object:
    return parse_config({
        "root_dir": str(root),
        "categories": {"apps": {"user": "root", "group": "root"}},
        "api": {"manifest": str(root / "etc" / "manifest.json")},
    })


def _service(root: Path, name: str, descriptor: dict | None) -> None:
    svc = root / "apps" / name
    svc.mkdir(parents=True)
    if descriptor is not None:
        (svc / "service.yaml").write_text(
            yaml.safe_dump(descriptor, sort_keys=False), encoding="utf-8")


class ParseTests(unittest.TestCase):
    def test_scaffold_template_parses_and_is_private_by_default(self) -> None:
        raw = yaml.safe_load(scaffold_template("apps", "demo"))
        meta, issues = parse_meta(raw, "apps", "demo")
        self.assertIsNotNone(meta)
        self.assertFalse(meta.public, issues)


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config = _config(self.root)
        _service(self.root, "public-one", {
            "schema": 1, "name": "Public", "icon": "🌐", "description": "d",
            "public": True, "url": "https://vault.coxyz.fr",
        })
        _service(self.root, "private-one", {
            "schema": 1, "name": "Private", "icon": "🔒", "description": "d",
            "public": False,
        })
        _service(self.root, "undescribed", None)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_only_public_descriptors_reach_the_manifest(self) -> None:
        result = build_manifest(self.config)
        self.assertEqual(["Public"], [s["name"] for s in result.manifest["services"]])
        self.assertEqual(1, result.private_count)

    def test_a_missing_descriptor_is_a_warning_not_an_error(self) -> None:
        result = build_manifest(self.config)
        self.assertEqual([], result.errors)
        self.assertTrue(any("undescribed" in w for w in result.warnings))

    def test_declared_urls_maps_service_to_url(self) -> None:
        self.assertEqual(
            {"apps/public-one": "https://vault.coxyz.fr"}, declared_urls(self.config),
        )

    def test_a_private_service_with_a_url_still_declares_it(self) -> None:
        # `clixz exposed` must see it: private in the dashboard says nothing
        # about whether the reverse proxy publishes it.
        _service(self.root, "hidden", {
            "schema": 1, "name": "H", "icon": "x", "description": "d",
            "public": False, "url": "https://komodo.coxyz.fr",
        })
        self.assertIn("apps/hidden", declared_urls(self.config))


class WriteManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config = _config(self.root)
        self.target = self.root / "etc" / "manifest.json"
        _service(self.root, "public-one", {
            "schema": 1, "name": "Public", "icon": "🌐", "description": "d", "public": True,
        })

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_writes_the_public_services_readable_by_everyone(self) -> None:
        result = write_manifest(self.config)
        self.assertEqual([], result.errors)
        written = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertEqual(["public-one"], [s["key"] for s in written["services"]])
        self.assertEqual(0o644, self.target.stat().st_mode & 0o777)

    def test_an_invalid_descriptor_leaves_the_previous_manifest_in_place(self) -> None:
        self.target.parent.mkdir(parents=True)
        self.target.write_text("previous", encoding="utf-8")
        _service(self.root, "broken", {"schema": 1, "public": "yes"})
        result = write_manifest(self.config)
        self.assertTrue(result.errors)
        self.assertEqual("previous", self.target.read_text(encoding="utf-8"))

