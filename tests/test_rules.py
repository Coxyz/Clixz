"""lint.yaml and ignore.yaml: the rules the operator owns, and the exceptions."""

from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

import yaml

from clixz.compose import lint_service
from clixz.config import load_config, parse_config
from clixz.policy import Severity, audit_service
from clixz.rules import (
    IGNORABLE_IDS,
    LINT_IDS,
    LINT_RULES,
    Policy,
    load_policy,
    parse_ignores,
    parse_lint,
    template,
)


class LintFileTests(unittest.TestCase):
    def test_an_empty_file_changes_nothing(self) -> None:
        issues: list[str] = []
        rules = parse_lint({}, issues)
        self.assertEqual({r.id: r.level for r in LINT_RULES}, rules.levels)
        self.assertEqual([], issues)

    def test_a_level_can_be_raised(self) -> None:
        rules = parse_lint({"rules": {"image-latest": "error"}}, [])
        found = lint_service("x", {"image": "a:latest"}, rules=rules)
        self.assertEqual(["error"], [f.level for f in found if f.rule == "image-latest"])

    def test_off_silences_a_rule(self) -> None:
        rules = parse_lint({"rules": {"no-healthcheck": "off"}}, [])
        found = lint_service("x", {"image": "a:1"}, rules=rules)
        self.assertNotIn("no-healthcheck", [f.rule for f in found])

    def test_unknown_rule_and_unknown_level_are_reported_not_applied(self) -> None:
        issues: list[str] = []
        rules = parse_lint({"rules": {"nope": "warn", "privileged": "loud"}}, issues)
        self.assertEqual("error", rules.level("privileged"))
        self.assertTrue(any("unknown rule 'nope'" in i for i in issues))
        self.assertTrue(any("rules.privileged" in i for i in issues))

    def test_a_mount_list_replaces_the_built_in_one(self) -> None:
        rules = parse_lint({"mounts": {"critical": ["/srv/secrets/"]}}, [])
        found = lint_service("x", {"image": "a:1", "volumes": ["/srv/secrets/k:/k:ro"]},
                             rules=rules)
        self.assertIn("mount-critical", [f.rule for f in found])
        found = lint_service("x", {"image": "a:1", "volumes": ["/root:/r"]}, rules=rules)
        self.assertNotIn("mount-critical", [f.rule for f in found])

    def test_a_relative_mount_path_is_refused(self) -> None:
        issues: list[str] = []
        parse_lint({"mounts": {"critical": ["etc"]}}, issues)
        self.assertTrue(any("absolute paths" in i for i in issues))

    def test_every_finding_carries_a_known_rule_id(self) -> None:
        body = {"privileged": True, "network_mode": "host", "pid": "host",
                "image": "a:latest", "ports": ["80:80"], "cap_add": ["NET_ADMIN"],
                "volumes": ["/:/rootfs", "/root:/r", "/etc/clixz:/c", "/etc/systemd:/s:ro",
                            "/opt/x:/x"]}
        found = lint_service("x", body, Path("/srv/docker/apps/x"))
        self.assertTrue(found)
        for finding in found:
            self.assertIn(finding.rule, LINT_IDS, finding.message)

    def test_the_bundled_template_is_the_defaults(self) -> None:
        issues: list[str] = []
        rules = parse_lint(yaml.safe_load(template("lint.yaml")), issues)
        self.assertEqual([], issues)
        self.assertEqual(dataclasses.asdict(parse_lint({}, [])), dataclasses.asdict(rules))


class IgnoreFileTests(unittest.TestCase):
    def _parse(self, *entries: dict) -> tuple[tuple, list[str]]:
        issues: list[str] = []
        return parse_ignores({"ignore": list(entries)}, issues), issues

    def test_an_entry_matches_its_service_and_rule_only(self) -> None:
        ignores, issues = self._parse(
            {"service": "automation/esphome", "rules": ["privileged"], "reason": "USB"})
        policy = Policy(ignores=ignores)
        self.assertEqual([], issues)
        self.assertIsNotNone(policy.ignored("automation/esphome", "privileged"))
        self.assertIsNone(policy.ignored("automation/esphome", "network-host"))
        self.assertIsNone(policy.ignored("apps/esphome", "privileged"))

    def test_globs(self) -> None:
        ignores, _ = self._parse(
            {"service": "apps/*", "rules": "no-healthcheck", "reason": "case by case"})
        policy = Policy(ignores=ignores)
        self.assertIsNotNone(policy.ignored("apps/atuin", "no-healthcheck"))
        self.assertIsNone(policy.ignored("infra/komodo", "no-healthcheck"))

    def test_an_entry_without_a_reason_is_reported_and_not_applied(self) -> None:
        ignores, issues = self._parse({"service": "apps/x", "rules": ["privileged"]})
        self.assertEqual((), ignores)
        self.assertTrue(any("no 'reason'" in i for i in issues))

    def test_an_unknown_rule_is_reported(self) -> None:
        ignores, issues = self._parse(
            {"service": "apps/x", "rules": ["privileged", "nope"], "reason": "r"})
        self.assertEqual(("privileged",), ignores[0].rules)
        self.assertTrue(any("nope" in i for i in issues))

    def test_permission_findings_are_ignorable_too(self) -> None:
        for rule in ("missing-dir", "missing-file", "owner", "mode", "acl"):
            self.assertIn(rule, IGNORABLE_IDS)

    def test_the_bundled_template_parses_clean_and_ignores_nothing(self) -> None:
        issues: list[str] = []
        self.assertEqual((), parse_ignores(yaml.safe_load(template("ignore.yaml")), issues))
        self.assertEqual([], issues)


class LoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_no_files_means_the_built_in_policy(self) -> None:
        policy = load_policy(self.dir)
        self.assertIsNone(policy.lint_source)
        self.assertEqual((), policy.ignores)
        self.assertEqual((), policy.issues)

    def test_a_broken_file_is_an_issue_not_a_crash(self) -> None:
        (self.dir / "lint.yaml").write_text("rules: [", encoding="utf-8")
        policy = load_policy(self.dir)
        self.assertTrue(any("lint.yaml" in i for i in policy.issues))
        self.assertEqual("error", policy.lint.level("privileged"))

    def test_the_files_are_read_from_next_to_the_config(self) -> None:
        (self.dir / "config.yaml").write_text(yaml.safe_dump({
            "root_dir": str(self.dir / "tree"),
            "categories": {"apps": {"user": "root", "group": "root"}},
        }), encoding="utf-8")
        (self.dir / "lint.yaml").write_text("rules: {image-latest: off}\n", encoding="utf-8")
        (self.dir / "ignore.yaml").write_text(yaml.safe_dump({"ignore": [
            {"service": "apps/demo", "rules": ["missing-file"], "reason": "no descriptor yet"},
        ]}), encoding="utf-8")
        config, _ = load_config(self.dir / "config.yaml")
        self.assertEqual("off", config.policy.lint.level("image-latest"))
        self.assertEqual(self.dir / "manifest.json", config.resolved_manifest_path)
        self.assertEqual(self.dir / "npm-hosts.json", config.resolved_npm_snapshot)

        (self.dir / "tree" / "apps" / "demo").mkdir(parents=True)
        report = audit_service(config, "apps", "demo")
        self.assertNotIn("missing-file", [f.rule for f in report.findings])
        self.assertEqual({"missing-file"}, {f.rule for f, _ in report.ignored})
        self.assertEqual({"no descriptor yet"}, {reason for _, reason in report.ignored})
        # The directories are still missing: only what was named is ignored.
        self.assertIs(Severity.ERROR, report.worst)

    def test_an_ignored_finding_is_not_fixed(self) -> None:
        tree = self.dir / "tree"
        (tree / "apps" / "demo").mkdir(parents=True)
        config = dataclasses.replace(
            parse_config({"root_dir": str(tree),
                          "categories": {"apps": {"user": "root", "group": "root"}}}),
            policy=Policy(ignores=parse_ignores({"ignore": [
                {"service": "apps/demo", "rules": ["missing-dir"], "reason": "stateless"},
            ]}, [])),
        )
        report = audit_service(config, "apps", "demo")
        self.assertFalse(any(fix[0] == "mkdir" for fix in report.fixes))


if __name__ == "__main__":
    unittest.main()
