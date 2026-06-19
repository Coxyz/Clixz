"""Tests for build mode: config/Dockerfile signal + komodo read overlay ACL."""

from __future__ import annotations

import getpass
import grp
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from coxyz.build import build_dirs, dockerfile_path, dockerfile_template, is_build_enabled
from coxyz.config import CategoryConfig, Config, PrincipalConfig, RuleConfig, SettingsConfig
from coxyz.policy import DevOverlay, Severity, apply_findings, audit_service, desired_acl
from coxyz.system import detect_acl_support, read_acl

PRINCIPAL_GROUP = "root"  # stand-in for the komodo group; resolves on any host


def _self_user() -> str:
    return getpass.getuser()


def _self_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def _config(root: Path) -> Config:
    # config_dir/data_dir carry no rule ACL — the komodo access is added solely
    # by build mode (mirrors the real config where data_dir has acl: null).
    return Config(
        root_dir=root,
        settings=SettingsConfig(
            principals={"komodo": PrincipalConfig(name=PRINCIPAL_GROUP, kind="group")}
        ),
        categories={"apps": CategoryConfig(user=_self_user(), group=_self_group())},
        rules={
            "category_dir": RuleConfig(mode="750", acl={"komodo": "rx"}),
            "service_dir": RuleConfig(mode="750", acl={"komodo": "rx"}),
            "compose_file": RuleConfig(mode="660", acl={"komodo": "rw"}),
            "config_dir": RuleConfig(mode="750", acl=None),
            "data_dir": RuleConfig(mode="750", acl=None),
            "env_file": RuleConfig(mode="600", owner="root:root", acl=None, audit_only=True),
        },
        exclude=[],
    )


class BuildHelpersTests(unittest.TestCase):
    def test_is_build_enabled_follows_dockerfile_presence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "apps" / "svc"
            (svc / "config").mkdir(parents=True)
            self.assertFalse(is_build_enabled(svc))
            dockerfile_path(svc).write_text("FROM scratch\n")
            self.assertTrue(is_build_enabled(svc))

    def test_build_dirs_are_existing_config_and_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "apps" / "svc"
            (svc / "config").mkdir(parents=True)
            self.assertEqual([svc / "config"], build_dirs(svc))
            (svc / "data").mkdir()
            self.assertEqual([svc / "config", svc / "data"], build_dirs(svc))

    def test_template_mentions_context(self) -> None:
        text = dockerfile_template("svc")
        self.assertIn("FROM", text)
        self.assertIn("data", text)


class BuildDesiredAclTests(unittest.TestCase):
    def test_build_overlay_adds_komodo_read_entry_and_default(self) -> None:
        cfg = _config(Path("/srv/docker"))
        overlay = DevOverlay(kind="group", name=PRINCIPAL_GROUP, perms="rx")
        acl = desired_acl(cfg.rule("config_dir"), cfg, build=overlay)
        self.assertEqual("rx", acl.named[("group", PRINCIPAL_GROUP)])
        self.assertEqual("rx", acl.mask)
        self.assertTrue(acl.has_default, "build paths expect a default ACL")


class BuildAuditIntegrationTests(unittest.TestCase):
    """A build-enabled service's config/ + data/ komodo ACL must not read as drift."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        if not detect_acl_support(self.root):
            self.tmp.cleanup()
            self.skipTest("filesystem has no ACL support")
        self.cfg = _config(self.root)
        self.svc = self.root / "apps" / "svc"
        self.config_dir = self.svc / "config"
        self.data_dir = self.svc / "data"
        self.config_dir.mkdir(parents=True)
        self.data_dir.mkdir()
        (self.svc / "compose.yaml").write_text("services: {}\n")
        # Baseline compliance first (owner/mode/komodo ACL on service_dir, …).
        apply_findings(self._drifts(), dry_run=False)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _drifts(self) -> list:
        report = audit_service(
            self.cfg, "apps", "svc", acl_enabled=True,
            principals_available={"komodo": True},
        )
        return [f for f in report.findings if f.severity is Severity.DRIFT]

    def _enable_build(self) -> None:
        dockerfile_path(self.svc).write_text(dockerfile_template("svc"))
        for path in (self.config_dir, self.data_dir):
            subprocess.run(["setfacl", "-R", "-m", f"g:{PRINCIPAL_GROUP}:rX", str(path)], check=True)
            subprocess.run(["setfacl", "-dR", "-m", f"g:{PRINCIPAL_GROUP}:rX", str(path)], check=True)

    def test_komodo_acl_not_drift_when_build_enabled(self) -> None:
        self._enable_build()
        names = {f.rule_name for f in self._drifts()}
        self.assertNotIn("config_dir", names)
        self.assertNotIn("data_dir", names)

    def test_komodo_acl_is_drift_when_not_build_enabled(self) -> None:
        # Grant the ACL but DON'T create the Dockerfile: it is unexpected → drift.
        for path in (self.config_dir, self.data_dir):
            subprocess.run(["setfacl", "-R", "-m", f"g:{PRINCIPAL_GROUP}:rX", str(path)], check=True)
        names = {f.rule_name for f in self._drifts()}
        self.assertIn("config_dir", names)

    def test_apply_grants_missing_komodo_acl_when_build_enabled(self) -> None:
        # Dockerfile present but ACL not yet granted → apply must add it and converge.
        dockerfile_path(self.svc).write_text(dockerfile_template("svc"))
        drifts = self._drifts()
        self.assertTrue({"config_dir", "data_dir"} & {f.rule_name for f in drifts})
        apply_findings(drifts, dry_run=False)

        acl = read_acl(self.config_dir)
        assert acl is not None
        self.assertEqual("rx", acl.named[("group", PRINCIPAL_GROUP)])
        self.assertTrue(acl.has_default)
        self.assertEqual([], self._drifts(), "second audit must find no drift")

    def test_build_fix_is_non_destructive(self) -> None:
        self._enable_build()
        # Break the base mode so config_dir drifts; fix must not use --set/-b/-k.
        subprocess.run(["setfacl", "-m", "u::rwx,g::rwx,o::---", str(self.config_dir)], check=True)
        finding = next(f for f in self._drifts() if f.rule_name == "config_dir")
        for cmd in finding.fixes:
            self.assertNotIn("--set", cmd)
            self.assertNotIn("-b", cmd)
            self.assertNotIn("-k", cmd)
        apply_findings([finding], dry_run=False)
        self.assertEqual([], [f for f in self._drifts() if f.rule_name == "config_dir"])


if __name__ == "__main__":
    unittest.main()
