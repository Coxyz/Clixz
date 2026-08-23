"""Tests for `archive`: nothing is destroyed unless --force is explicitly given."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from coxyz.archive import ARCHIVE_DIRNAME, archive_root, archive_service, list_archived
from coxyz.config import CategoryConfig, Config, PrincipalConfig, RuleConfig, SettingsConfig


def _config(root: Path) -> Config:
    return Config(
        root_dir=root,
        settings=SettingsConfig(principals={"komodo": PrincipalConfig(name="root", kind="group")}),
        categories={"apps": CategoryConfig(user="root", group="root")},
        rules={"service_dir": RuleConfig(mode="750")},
        exclude=[],
    )


def _service(root: Path, name: str = "demo") -> Path:
    svc = root / "apps" / name
    (svc / "data").mkdir(parents=True)
    (svc / "compose.yaml").write_text("services:\n  demo:\n    image: nginx\n", encoding="utf-8")
    (svc / ".env").write_text("SECRET=hunter2\n", encoding="utf-8")
    (svc / "data" / "db.sqlite").write_text("payload", encoding="utf-8")
    return svc


class ArchiveTests(unittest.TestCase):
    def test_moves_the_tree_instead_of_deleting_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            svc = _service(root)
            result = archive_service(_config(root), "apps", "demo", dry_run=False)

            self.assertFalse(svc.exists())
            self.assertIsNotNone(result.destination)
            self.assertTrue(result.destination.is_dir())
            # Contents survive intact, including data and secrets.
            self.assertEqual(
                (result.destination / ".env").read_text(encoding="utf-8"), "SECRET=hunter2\n"
            )
            self.assertEqual(
                (result.destination / "data" / "db.sqlite").read_text(encoding="utf-8"), "payload"
            )

    def test_archive_root_is_not_world_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _service(root)
            archive_service(_config(root), "apps", "demo", dry_run=False)
            mode = archive_root(_config(root)).stat().st_mode & 0o777
            self.assertEqual(mode, 0o700)

    def test_archive_dir_is_hidden_from_category_discovery(self) -> None:
        # `.archive` is a dotted name and not a configured category, so the
        # normal walk cannot mistake it for one.
        self.assertTrue(ARCHIVE_DIRNAME.startswith("."))
        self.assertNotIn(ARCHIVE_DIRNAME, _config(Path("/tmp")).categories)

    def test_force_deletes_and_leaves_no_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            svc = _service(root)
            result = archive_service(_config(root), "apps", "demo", dry_run=False, force=True)

            self.assertFalse(svc.exists())
            self.assertTrue(result.forced)
            self.assertIsNone(result.destination)
            self.assertFalse(archive_root(_config(root)).exists())

    def test_dry_run_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            svc = _service(root)
            archive_service(_config(root), "apps", "demo", dry_run=True)
            self.assertTrue(svc.is_dir())
            self.assertTrue((svc / ".env").is_file())

    def test_rejects_unknown_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _service(root)
            with self.assertRaises(RuntimeError):
                archive_service(_config(root), "apps", "ghost", dry_run=False)

    def test_refuses_a_symlinked_service_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "apps").mkdir(parents=True)
            outside = root / "elsewhere"
            outside.mkdir()
            (outside / "keep.txt").write_text("important", encoding="utf-8")
            (root / "apps" / "demo").symlink_to(outside)

            with self.assertRaises(RuntimeError):
                archive_service(_config(root), "apps", "demo", dry_run=False, force=True)
            self.assertTrue((outside / "keep.txt").is_file())

    def test_list_archived_reports_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _service(root, "one")
            _service(root, "two")
            cfg = _config(root)
            archive_service(cfg, "apps", "one", dry_run=False)
            archive_service(cfg, "apps", "two", dry_run=False)

            entries = list_archived(cfg)
            self.assertEqual({(c, s) for c, s, _, _ in entries}, {("apps", "one"), ("apps", "two")})

    def test_list_archived_skips_the_updates_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = _config(root)
            updates = archive_root(cfg) / "apps" / "demo" / "updates"
            updates.mkdir(parents=True)
            (updates / "20260101T000000Z-compose.yaml").write_text("x", encoding="utf-8")
            self.assertEqual(list_archived(cfg), [])


if __name__ == "__main__":
    unittest.main()
