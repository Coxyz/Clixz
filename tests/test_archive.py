"""Archiving instead of deleting."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from clixz.archive import archive_root, archive_service, list_archived
from clixz.config import parse_config


def _config(root: Path) -> object:
    return parse_config({
        "root_dir": str(root),
        "categories": {"apps": {"user": "root", "group": "root"}},
    })


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config = _config(self.root)
        self.svc = self.root / "apps" / "demo"
        (self.svc / "data").mkdir(parents=True)
        (self.svc / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_moves_the_tree_under_archive(self) -> None:
        result = archive_service(self.config, "apps", "demo", dry_run=False)
        self.assertFalse(self.svc.exists())
        self.assertTrue((result.destination / "compose.yaml").is_file())

    def test_archived_service_disappears_from_listings(self) -> None:
        archive_service(self.config, "apps", "demo", dry_run=False)
        from clixz.policy import list_services
        self.assertEqual([], list_services(self.config))

    def test_list_archived_finds_it(self) -> None:
        archive_service(self.config, "apps", "demo", dry_run=False)
        entries = list_archived(self.config)
        self.assertEqual([("apps", "demo")], [(c, s) for c, s, _, _ in entries])

    def test_dry_run_changes_nothing(self) -> None:
        archive_service(self.config, "apps", "demo", dry_run=True)
        self.assertTrue(self.svc.exists())
        self.assertFalse(archive_root(self.config).exists())

    def test_unknown_service_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            archive_service(self.config, "apps", "ghost", dry_run=False)

    def test_a_symlinked_service_is_refused(self) -> None:
        # Otherwise `mv` would move whatever it points at, anywhere on the host.
        outside = self.root / "outside"
        outside.mkdir()
        link = self.root / "apps" / "linked"
        link.symlink_to(outside)
        with self.assertRaises(RuntimeError):
            archive_service(self.config, "apps", "linked", dry_run=False)
        self.assertTrue(outside.exists())
