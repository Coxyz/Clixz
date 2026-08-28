"""Tests for the ACL model and the audit/apply pipeline."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from clixz.config import (
    CategoryConfig,
    Config,
    PrincipalConfig,
    RuleConfig,
    SettingsConfig,
)
from clixz.policy import (
    DevOverlay,
    Severity,
    acl_set_spec,
    apply_findings,
    audit_service,
    desired_acl,
)
from clixz.system import (
    Acl,
    detect_acl_support,
    mode_to_perms,
    normalize_perms,
    octal_digit_to_perms,
    perms_to_symbolic,
    read_acl,
    union_perms,
)

# A principal that resolves on any Linux host, used as a stand-in for komodo.
PRINCIPAL_GROUP = "root"


def _make_config(root: Path, owner_user: str, owner_group: str) -> Config:
    return Config(
        root_dir=root,
        settings=SettingsConfig(
            principals={"komodo": PrincipalConfig(name=PRINCIPAL_GROUP, kind="group")}
        ),
        categories={"apps": CategoryConfig(user=owner_user, group=owner_group)},
        rules={
            "category_dir": RuleConfig(mode="750", acl={"komodo": "rx"}),
            "service_dir": RuleConfig(mode="750", acl={"komodo": "rx"}),
            "compose_file": RuleConfig(mode="660", acl={"komodo": "rw"}),
            "config_dir": RuleConfig(mode="750", acl={"komodo": "x"}),
            "data_dir": RuleConfig(mode="750", acl=None, audit_only=True),
            "env_file": RuleConfig(mode="600", owner="root:root", acl=None, audit_only=True),
        },
        exclude=[],
    )


class PermHelperTests(unittest.TestCase):
    def test_octal_digit_to_perms(self) -> None:
        self.assertEqual("rwx", octal_digit_to_perms(7))
        self.assertEqual("rx", octal_digit_to_perms(5))
        self.assertEqual("", octal_digit_to_perms(0))

    def test_mode_to_perms(self) -> None:
        self.assertEqual(("rwx", "rx", ""), mode_to_perms("750"))
        self.assertEqual(("rw", "rw", ""), mode_to_perms("660"))

    def test_normalize_perms_is_order_independent(self) -> None:
        self.assertEqual("rx", normalize_perms("r-x"))
        self.assertEqual("rwx", normalize_perms("xrw"))
        self.assertEqual("", normalize_perms("---"))

    def test_perms_to_symbolic(self) -> None:
        self.assertEqual("r-x", perms_to_symbolic("rx"))
        self.assertEqual("---", perms_to_symbolic(""))
        self.assertEqual("rwx", perms_to_symbolic("rwx"))

    def test_union_perms(self) -> None:
        self.assertEqual("rwx", union_perms("rx", "rw"))
        self.assertEqual("rx", union_perms("rx", "x", ""))


class AclSpecTests(unittest.TestCase):
    def test_acl_set_spec_encodes_mode_and_named_entry(self) -> None:
        cfg = _make_config(Path("/srv/docker"), "svc", "svc")
        spec = acl_set_spec(cfg.rule("service_dir"), cfg)
        self.assertEqual(f"u::rwx,g::r-x,o::---,g:{PRINCIPAL_GROUP}:r-x", spec)

    def test_desired_acl_mask_is_union_of_group_and_named(self) -> None:
        cfg = _make_config(Path("/srv/docker"), "svc", "svc")
        # config_dir: group r-x, komodo --x  ->  mask must be r-x.
        acl = desired_acl(cfg.rule("config_dir"), cfg)
        self.assertEqual("rx", acl.mask)
        self.assertEqual("x", acl.named[("group", PRINCIPAL_GROUP)])


class AclFixPlanningTests(unittest.TestCase):
    """The fix for an ACL path must never be a chmod (it would clobber the mask)."""

    def test_acl_drift_is_fixed_by_a_single_setfacl_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if not detect_acl_support(Path(tmp)):
                self.skipTest("filesystem has no ACL support")
            cfg = _make_config(Path(tmp), _self_user(), _self_group())
            svc = Path(tmp) / "apps" / "svc"
            svc.mkdir(parents=True)
            (svc / "config").mkdir()
            (svc / "data").mkdir()
            (svc / "compose.yaml").write_text("services: {}\n")

            report = audit_service(
                cfg, "apps", "svc", acl_enabled=True,
                principals_available={"komodo": True},
            )
            svc_finding = next(f for f in report.findings if f.rule_name == "service_dir")
            self.assertIs(Severity.DRIFT, svc_finding.severity)
            self.assertTrue(svc_finding.fixes)
            for command in svc_finding.fixes:
                self.assertNotEqual("chmod", command[0],
                                    "ACL paths must not be fixed with chmod")


class RecursiveAclTests(unittest.TestCase):
    """`recursive: true` propagates a rule's owner, mode and ACL to existing children."""

    def _config_with_recursive_config_dir(self, root: Path) -> Config:
        cfg = _make_config(root, _self_user(), _self_group())
        rules = dict(cfg.rules)
        rules["config_dir"] = RuleConfig(mode="750", acl={"komodo": "x"}, recursive=True)
        return Config(
            root_dir=cfg.root_dir, settings=cfg.settings, categories=cfg.categories,
            rules=rules, exclude=cfg.exclude,
        )

    def test_recursive_rule_plans_setfacl_dash_r_and_dash_dr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if not detect_acl_support(root):
                self.skipTest("filesystem has no ACL support")
            cfg = self._config_with_recursive_config_dir(root)
            svc = root / "apps" / "svc"
            (svc / "config").mkdir(parents=True)
            (svc / "data").mkdir()
            (svc / "compose.yaml").write_text("services: {}\n")

            report = audit_service(
                cfg, "apps", "svc", acl_enabled=True,
                principals_available={"komodo": True},
            )
            config_finding = next(f for f in report.findings if f.rule_name == "config_dir")
            self.assertIs(Severity.DRIFT, config_finding.severity)
            kinds = [cmd[:2] for cmd in config_finding.fixes if cmd[0] == "setfacl"]
            self.assertIn(["setfacl", "-R"], kinds)
            self.assertIn(["setfacl", "-dR"], kinds)
            self.assertTrue(
                any(cmd[:2] == ["chown", "-R"] for cmd in config_finding.fixes),
                "recursive must also reapply owner to existing children",
            )
            self.assertFalse(
                any(cmd[0] == "chmod" for cmd in config_finding.fixes),
                "an ACL-managed recursive fix must never chmod (would clobber the mask)",
            )

    def test_recursive_rule_without_acl_uses_chmod_dash_r(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = _make_config(root, _self_user(), _self_group())
            rules = dict(cfg.rules)
            rules["config_dir"] = RuleConfig(mode="750", recursive=True)
            cfg = Config(
                root_dir=cfg.root_dir, settings=cfg.settings, categories=cfg.categories,
                rules=rules, exclude=cfg.exclude,
            )
            svc = root / "apps" / "svc"
            (svc / "config").mkdir(parents=True, mode=0o700)
            (svc / "data").mkdir()
            (svc / "compose.yaml").write_text("services: {}\n")

            report = audit_service(
                cfg, "apps", "svc", acl_enabled=True,
                principals_available={"komodo": True},
            )
            config_finding = next(f for f in report.findings if f.rule_name == "config_dir")
            self.assertIs(Severity.DRIFT, config_finding.severity)
            self.assertIn(["chmod", "-R", "750", str(svc / "config")], config_finding.fixes)

    def test_non_recursive_rule_has_no_dash_r_fix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if not detect_acl_support(root):
                self.skipTest("filesystem has no ACL support")
            cfg = _make_config(root, _self_user(), _self_group())
            svc = root / "apps" / "svc"
            (svc / "config").mkdir(parents=True)
            (svc / "data").mkdir()
            (svc / "compose.yaml").write_text("services: {}\n")

            report = audit_service(
                cfg, "apps", "svc", acl_enabled=True,
                principals_available={"komodo": True},
            )
            config_finding = next(f for f in report.findings if f.rule_name == "config_dir")
            self.assertIs(Severity.DRIFT, config_finding.severity)
            for cmd in config_finding.fixes:
                if cmd[0] == "setfacl":
                    self.assertNotIn("-R", cmd)
                    self.assertNotIn("-dR", cmd)

    def test_apply_recursive_grants_access_on_nested_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if not detect_acl_support(root):
                self.skipTest("filesystem has no ACL support")
            cfg = self._config_with_recursive_config_dir(root)
            svc = root / "apps" / "svc"
            (svc / "config").mkdir(parents=True)
            (svc / "data").mkdir()
            (svc / "compose.yaml").write_text("services: {}\n")
            nested = svc / "config" / "nested.conf"
            nested.write_text("x\n")

            report = audit_service(
                cfg, "apps", "svc", acl_enabled=True,
                principals_available={"komodo": True},
            )
            apply_findings(report.findings, dry_run=False)

            nested_acl = read_acl(nested)
            assert nested_acl is not None
            self.assertEqual("x", nested_acl.named[("group", PRINCIPAL_GROUP)])

            new_file = svc / "config" / "new.conf"
            new_file.write_text("y\n")
            new_acl = read_acl(new_file)
            assert new_acl is not None
            self.assertEqual(
                "x", new_acl.named[("group", PRINCIPAL_GROUP)],
                "default ACL must make the entry inherit onto new files",
            )


class AclApplyIntegrationTests(unittest.TestCase):
    """Apply real setfacl and verify effective rights are never restricted."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        if not detect_acl_support(self.root):
            self.tmp.cleanup()
            self.skipTest("filesystem has no ACL support")
        self.cfg = _make_config(self.root, _self_user(), _self_group())
        self.svc = self.root / "apps" / "svc"
        self.svc.mkdir(parents=True)
        (self.svc / "config").mkdir()
        (self.svc / "data").mkdir()
        (self.svc / "compose.yaml").write_text("services: {}\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _audit_drifts(self) -> list:
        report = audit_service(
            self.cfg, "apps", "svc", acl_enabled=True,
            principals_available={"komodo": True},
        )
        return [f for f in report.findings if f.severity is Severity.DRIFT]

    def test_apply_leaves_no_effective_restriction(self) -> None:
        # A too-narrow mask is the exact bug: the entry says rwx, the mask r--.
        subprocess.run(
            ["setfacl", "-m", f"g:{PRINCIPAL_GROUP}:rwx", "-m", "m:r", str(self.svc)],
            check=True,
        )
        apply_findings(self._audit_drifts(), dry_run=False)

        out = subprocess.run(
            ["getfacl", "-pc", str(self.svc)], capture_output=True, text=True,
        ).stdout
        self.assertNotIn("#effective", out,
                         "mask must not restrict any ACL entry after apply")

        acl = read_acl(self.svc)
        assert acl is not None
        self.assertEqual("rx", acl.named[("group", PRINCIPAL_GROUP)])
        self.assertEqual("rx", acl.mask)

    def test_apply_is_idempotent(self) -> None:
        subprocess.run(["chmod", "700", str(self.svc)], check=True)
        apply_findings(self._audit_drifts(), dry_run=False)
        self.assertEqual([], self._audit_drifts(), "second audit must find no drift")

    def test_audit_detects_narrow_mask_only(self) -> None:
        # Set the correct ACL, then break only the mask.
        subprocess.run(
            ["setfacl", "-k", "--set", acl_set_spec(self.cfg.rule("service_dir"), self.cfg),
             str(self.svc)],
            check=True,
        )
        subprocess.run(["setfacl", "-m", "m:r", str(self.svc)], check=True)

        svc_finding = next(
            f for f in self._audit_drifts() if f.rule_name == "service_dir"
        )
        self.assertTrue(any("mask" in issue for issue in svc_finding.issues))


class DevAwareDesiredAclTests(unittest.TestCase):
    """A dev-enabled config/ or data/ expects the dev entry + a default ACL."""

    def test_dev_overlay_adds_entry_default_and_widens_mask(self) -> None:
        cfg = _make_config(Path("/srv/docker"), "svc", "svc")
        overlay = DevOverlay(kind="user", name="boxyz_dev", perms="rwx")
        # config_dir: group r-x, komodo --x, dev rwx -> mask must widen to rwx.
        acl = desired_acl(cfg.rule("config_dir"), cfg, dev=overlay)
        self.assertEqual("rwx", acl.named[("user", "boxyz_dev")])
        self.assertEqual("x", acl.named[("group", PRINCIPAL_GROUP)])
        self.assertEqual("rwx", acl.mask)
        self.assertTrue(acl.has_default, "dev paths expect a default ACL")


class DevAwareAuditIntegrationTests(unittest.TestCase):
    """A dev-enabled service's config/ + data/ ACL must not read as drift."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        if not detect_acl_support(self.root):
            self.tmp.cleanup()
            self.skipTest("filesystem has no ACL support")
        # config_dir/data_dir carry no rule ACL — only the dev overlay (matches
        # the real config where dev access is managed entirely by `clixz dev`).
        self.cfg = Config(
            root_dir=self.root,
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
        self.svc = self.root / "apps" / "svc"
        self.svc.mkdir(parents=True)
        self.config_dir = self.svc / "config"
        self.config_dir.mkdir()
        (self.svc / "data").mkdir()
        (self.svc / "compose.yaml").write_text("services: {}\n")
        # Bring the service tree to compliance first (owner/mode/komodo ACL).
        apply_findings(self._drifts(dev=None), dry_run=False)
        # Then enable dev: grant a recursive user ACL + default, like `dev add`.
        self.overlay = DevOverlay(kind="user", name=_self_user(), perms="rwx")
        for path in (self.config_dir, self.svc / "data"):
            subprocess.run(["setfacl", "-R", "-m", f"u:{_self_user()}:rwX", str(path)], check=True)
            subprocess.run(["setfacl", "-dR", "-m", f"u:{_self_user()}:rwX", str(path)], check=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _drifts(self, *, dev: DevOverlay | None) -> list:
        report = audit_service(
            self.cfg, "apps", "svc", acl_enabled=True,
            principals_available={"komodo": True}, dev=dev,
        )
        return [f for f in report.findings if f.severity is Severity.DRIFT]

    def test_dev_acl_is_not_drift_when_dev_enabled(self) -> None:
        drifts = self._drifts(dev=self.overlay)
        offenders = [f.rule_name for f in drifts]
        self.assertNotIn("config_dir", offenders)
        self.assertNotIn("data_dir", offenders)

    def test_dev_acl_is_drift_when_not_dev_enabled(self) -> None:
        # Same on-disk state, but the service is no longer dev-enabled: the
        # leftover dev ACL is correctly flagged for removal.
        names = {f.rule_name for f in self._drifts(dev=None)}
        self.assertIn("config_dir", names)

    def test_dev_fix_never_wipes_with_set_or_bare(self) -> None:
        # Break the base mode so the dev path drifts, then check the fix is
        # non-destructive (no `--set`, no `-b`/`-k` that would drop the dev ACL).
        subprocess.run(["setfacl", "-m", "u::rwx,g::rwx,o::---", str(self.config_dir)], check=True)
        finding = next(
            f for f in self._drifts(dev=self.overlay) if f.rule_name == "config_dir"
        )
        for cmd in finding.fixes:
            self.assertNotIn("--set", cmd)
            self.assertNotIn("-b", cmd)
            self.assertNotIn("-k", cmd)
        # And applying it converges.
        apply_findings([finding], dry_run=False)
        self.assertEqual([], [f for f in self._drifts(dev=self.overlay)
                              if f.rule_name == "config_dir"])


def _self_user() -> str:
    import getpass
    return getpass.getuser()


def _self_group() -> str:
    import grp
    import os
    return grp.getgrgid(os.getgid()).gr_name


if __name__ == "__main__":
    unittest.main()
