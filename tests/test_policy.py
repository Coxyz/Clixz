"""Audit of ownership and modes over a temporary service tree."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from clixz.config import parse_config
from clixz.policy import (
    Severity,
    audit_service,
    is_excluded,
    list_services,
    order_fixes,
    resolve_service,
    unknown_category_dirs,
)


def _config(root: Path, owner: str) -> object:
    user, _, group = owner.partition(":")
    return parse_config({
        "root_dir": str(root),
        "categories": {
            "apps": {"user": user, "group": group},
            "infra": {"user": user, "group": group},
        },
        "rules": {"dir": {"mode": "750"}, "file": {"mode": "640"},
                  "env": {"mode": "600", "owner": owner}},
    })


def _make_tree(root: Path, category: str, service: str) -> Path:
    svc = root / category / service
    (svc / "config").mkdir(parents=True)
    (svc / "data").mkdir()
    for path, mode in ((svc / "compose.yaml", 0o640),
                       (svc / "service.yaml", 0o640),
                       (svc / ".env", 0o600)):
        path.write_text("", encoding="utf-8")
        path.chmod(mode)
    for path in (root / category, svc, svc / "config", svc / "data"):
        path.chmod(0o750)
    return svc


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        import grp
        import pwd
        self.owner = (f"{pwd.getpwuid(os.getuid()).pw_name}:"
                      f"{grp.getgrgid(os.getgid()).gr_name}")
        self.config = _config(self.root, self.owner)
        self.svc = _make_tree(self.root, "apps", "demo")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_correct_tree_is_clean(self) -> None:
        report = audit_service(self.config, "apps", "demo")
        self.assertEqual(Severity.OK, report.worst, [f.message for f in report.findings])

    def test_wrong_mode_is_an_error_with_a_fix(self) -> None:
        (self.svc / "compose.yaml").chmod(0o664)
        report = audit_service(self.config, "apps", "demo")
        bad = [f for f in report.findings if f.severity is Severity.ERROR]
        self.assertEqual(1, len(bad))
        self.assertIn("mode is 664", bad[0].message)
        self.assertEqual("chmod", bad[0].fix[0])

    def test_missing_directory_is_an_error_and_fixable(self) -> None:
        (self.svc / "data").rmdir()
        report = audit_service(self.config, "apps", "demo")
        bad = [f for f in report.findings if f.severity is Severity.ERROR]
        self.assertEqual(["mkdir"], [f.fix[0] for f in bad])

    def test_missing_file_is_only_a_warning(self) -> None:
        # An absent compose.yaml is a service in progress, not a policy breach —
        # and clixz has no business inventing its content.
        (self.svc / "compose.yaml").unlink()
        report = audit_service(self.config, "apps", "demo")
        self.assertEqual(Severity.WARN, report.worst)

    def test_data_contents_are_never_audited(self) -> None:
        rogue = self.svc / "data" / "state.db"
        rogue.write_text("x", encoding="utf-8")
        rogue.chmod(0o777)
        report = audit_service(self.config, "apps", "demo")
        self.assertEqual(Severity.OK, report.worst)
        self.assertNotIn(str(rogue), [str(f.path) for f in report.findings])

    def test_config_contents_are_never_audited(self) -> None:
        rogue = self.svc / "config" / "app.conf"
        rogue.write_text("x", encoding="utf-8")
        rogue.chmod(0o666)
        self.assertEqual(Severity.OK, audit_service(self.config, "apps", "demo").worst)


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        import grp
        import pwd
        owner = (f"{pwd.getpwuid(os.getuid()).pw_name}:"
                 f"{grp.getgrgid(os.getgid()).gr_name}")
        self.config = _config(self.root, owner)
        _make_tree(self.root, "apps", "demo")
        _make_tree(self.root, "infra", "demo")
        _make_tree(self.root, "apps", "other")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_lists_every_service(self) -> None:
        self.assertEqual(
            [("apps", "demo"), ("apps", "other"), ("infra", "demo")],
            [(c, s) for c, s, _ in list_services(self.config)],
        )

    def test_qualified_name_resolves(self) -> None:
        category, service, _ = resolve_service(self.config, "infra/demo")
        self.assertEqual(("infra", "demo"), (category, service))

    def test_ambiguous_bare_name_is_refused_rather_than_guessed(self) -> None:
        with self.assertRaises(KeyError) as ctx:
            resolve_service(self.config, "demo")
        self.assertIn("Ambiguous", str(ctx.exception))

    def test_unique_bare_name_resolves(self) -> None:
        self.assertEqual("other", resolve_service(self.config, "other")[1])

    def test_undeclared_directory_is_reported_not_removed(self) -> None:
        (self.root / "scratch").mkdir()
        self.assertEqual(["scratch"], [p.name for p in unknown_category_dirs(self.config)])

    def test_dot_directories_are_invisible(self) -> None:
        (self.root / ".archive").mkdir()
        self.assertEqual([], unknown_category_dirs(self.config))

    def test_exclude_hides_a_service(self) -> None:
        config = parse_config({
            "root_dir": str(self.root),
            "categories": {"apps": {"user": "root", "group": "root"}},
            "exclude": [str(self.root / "apps" / "other")],
        })
        self.assertTrue(is_excluded(config, self.root / "apps" / "other"))
        self.assertNotIn("other", [s for _, s, _ in list_services(config)])


    def test_an_excluded_path_inside_a_service_is_neither_audited_nor_fixed(self) -> None:
        svc = self.root / "apps" / "demo"
        (svc / "config").chmod(0o700)
        config = parse_config({
            "root_dir": str(self.root),
            "categories": {"apps": {"user": "root", "group": "root"}},
            "exclude": [str(svc / "config")],
        })
        report = audit_service(config, "apps", "demo")
        self.assertNotIn(svc / "config", [f.path for f in report.findings])
        self.assertFalse(any(str(svc / "config") in fix for fix in report.fixes))
        # The rest of the service is still audited.
        self.assertIn(svc / "data", [f.path for f in report.findings])

    def test_exclusion_stops_at_a_path_boundary(self) -> None:
        config = parse_config({
            "root_dir": str(self.root),
            "categories": {"apps": {"user": "root", "group": "root"}},
            "exclude": [str(self.root / "apps" / "komodo")],
        })
        self.assertTrue(is_excluded(config, self.root / "apps" / "komodo" / "config"))
        self.assertFalse(is_excluded(config, self.root / "apps" / "komodo-periphery"))


class OrderingTests(unittest.TestCase):
    def test_mkdir_before_chown_before_chmod(self) -> None:
        ordered = order_fixes([
            ["chmod", "750", "/a"], ["chown", "u:g", "/a"], ["mkdir", "-p", "/a"],
        ])
        self.assertEqual(["mkdir", "chown", "chmod"], [c[0] for c in ordered])

    def test_acl_is_stripped_before_chmod(self) -> None:
        # On a path with an extended ACL, chmod writes the mask rather than the
        # group bits: `chmod 640` then `setfacl -b` does not leave 640.
        ordered = order_fixes([
            ["chmod", "640", "/a"], ["setfacl", "-b", "/a"], ["chown", "u:g", "/a"],
        ])
        self.assertEqual(["setfacl", "chown", "chmod"], [c[0] for c in ordered])

    def test_duplicates_are_collapsed(self) -> None:
        self.assertEqual(1, len(order_fixes([["chmod", "750", "/a"]] * 3)))

    def test_parents_are_fixed_before_children(self) -> None:
        ordered = order_fixes([
            ["mkdir", "-p", "/a/b/c"], ["mkdir", "-p", "/a"], ["mkdir", "-p", "/a/b"],
        ])
        self.assertEqual(["/a", "/a/b", "/a/b/c"], [c[-1] for c in ordered])
