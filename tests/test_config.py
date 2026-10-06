"""Config parsing, structural validation, and the v1 → v2 migration."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from clixz.config import DEFAULT_RULES, migrate_raw, parse_config, validate_config


def _v2() -> dict:
    return {
        "root_dir": "/srv/docker",
        "categories": {"apps": {"user": "svc_apps", "group": "svc_apps"}},
        "rules": {"dir": {"mode": "750"}, "file": {"mode": "640"},
                  "env": {"mode": "600", "owner": "root:root"}},
    }


def _v1() -> dict:
    return {
        "root_dir": "/srv/docker",
        "settings": {"principals": {"komodo": {"name": "boxyz_komodo", "kind": "group"}}},
        "categories": {"apps": {"user": "svc_apps", "group": "svc_apps"}},
        "rules": {
            "category_dir": {"mode": "750", "acl": {"komodo": "rx"}},
            "service_dir": {"mode": "750", "acl": {"komodo": "rx"}},
            "compose_file": {"mode": "660", "acl": {"komodo": "rw"}},
            "config_dir": {"mode": "750"},
            "data_dir": {"mode": "750"},
            "env_file": {"mode": "600", "owner": "root:root", "acl": {"docker": "r"}},
        },
        "dev": {"compose": "/srv/docker/apps/code-boxyz/compose.yaml"},
        "repos": {"dir": "/opt/repos"},
        "api": {"manifest": "/srv/docker/apps/api/data/manifest.json"},
    }


class ValidateTests(unittest.TestCase):
    def test_clean_v2_config_has_no_issues(self) -> None:
        self.assertEqual([], validate_config(_v2()))

    def test_missing_root_dir(self) -> None:
        cfg = _v2()
        del cfg["root_dir"]
        self.assertTrue(any("root_dir" in i for i in validate_config(cfg)))

    def test_retired_rule_names_point_at_their_replacement(self) -> None:
        issues = validate_config(_v1())
        self.assertTrue(any("rules.compose_file" in i and "rules.file" in i for i in issues))
        self.assertTrue(any("rules.env_file" in i and "rules.env" in i for i in issues))

    def test_retired_sections_explain_themselves(self) -> None:
        issues = validate_config(_v1())
        self.assertTrue(any(i.startswith("'settings' was retired") for i in issues))
        self.assertTrue(any(i.startswith("'dev' was retired") for i in issues))

    def test_repos_is_back_with_one_key_and_its_v1_keys_stay_retired(self) -> None:
        self.assertEqual([], validate_config(_v2() | {"repos": {"dir": "/opt/repos"}}))
        issues = validate_config(_v2() | {"repos": {"dir": "/opt/repos", "mode": "775"}})
        self.assertTrue(any(i.startswith("repos.mode was retired") for i in issues))

    def test_unknown_rule_is_reported(self) -> None:
        cfg = _v2()
        cfg["rules"]["sockets"] = {"mode": "660"}
        self.assertTrue(any("unknown rule 'sockets'" in i for i in validate_config(cfg)))

    def test_unknown_top_level_key(self) -> None:
        cfg = _v2()
        cfg["nope"] = 1
        self.assertTrue(any("unknown top-level key 'nope'" in i for i in validate_config(cfg)))


class ParseTests(unittest.TestCase):
    def test_omitted_rules_fall_back_to_defaults(self) -> None:
        cfg = parse_config({"root_dir": "/srv/docker",
                            "categories": {"apps": {"user": "u", "group": "g"}}})
        self.assertEqual(DEFAULT_RULES["dir"].mode, cfg.rule("dir").mode)
        self.assertEqual("root:root", cfg.rule("env").owner)

    def test_category_owner(self) -> None:
        cfg = parse_config(_v2())
        self.assertEqual("svc_apps:svc_apps", cfg.category("apps").owner)

    def test_unknown_category_names_the_known_ones(self) -> None:
        cfg = parse_config(_v2())
        with self.assertRaises(KeyError) as ctx:
            cfg.category("nope")
        self.assertIn("apps", str(ctx.exception))

    def test_v1_rule_names_are_ignored_rather_than_misapplied(self) -> None:
        # A v1 file still loads: its retired rules are reported by
        # validate_config, but they must never silently become v2 rules.
        cfg = parse_config(_v1())
        self.assertEqual("640", cfg.rule("file").mode)  # not 660 from compose_file

    def test_npm_section(self) -> None:
        cfg = parse_config(_v2() | {"npm": {"database": "/tmp/db.sqlite"}})
        self.assertEqual("/tmp/db.sqlite", str(cfg.npm.database))

    def test_without_an_npm_section_the_database_is_looked_for_in_the_tree(self) -> None:
        # The migrated host config had no `npm` key, and `clixz exposed` then
        # answered "nothing configured" on a host that runs NPM.
        self.assertEqual("/srv/docker/network/npm/data/app/database.sqlite",
                         str(parse_config(_v2()).npm.database))

    def test_npm_can_be_disabled_explicitly(self) -> None:
        self.assertIsNone(parse_config(_v2() | {"npm": {"database": None}}).npm.database)

    def test_generated_files_default_to_next_to_the_config(self) -> None:
        cfg = parse_config(_v2())
        self.assertEqual("/etc/clixz/manifest.json", str(cfg.resolved_manifest_path))

    def test_repos_dir(self) -> None:
        self.assertEqual("/opt/repos", str(parse_config(_v2()).repos_dir))
        cfg = parse_config(_v2() | {"repos": {"dir": "/srv/git"}})
        self.assertEqual("/srv/git", str(cfg.repos_dir))


class StateTests(unittest.TestCase):
    def test_state_defaults_to_var_lib_clixz_and_the_docker_group(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLIXZ_STATE_DIR", None)
            state = parse_config(_v2()).state
        self.assertEqual(Path("/var/lib/clixz"), state.dir)
        self.assertEqual("docker", state.group)
        self.assertEqual(Path("/var/lib/clixz/plans"), state.plans_dir)
        self.assertEqual(Path("/var/lib/clixz/todo.yaml"), state.todo_file)

    def test_state_section_overrides_the_defaults(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLIXZ_STATE_DIR", None)
            state = parse_config(_v2() | {"state": {"dir": "/srv/state", "group": "ops"}}).state
        self.assertEqual(Path("/srv/state"), state.dir)
        self.assertEqual("ops", state.group)

    def test_the_environment_wins_over_the_config(self) -> None:
        with mock.patch.dict(os.environ, {"CLIXZ_STATE_DIR": "/tmp/clixz-state"}):
            state = parse_config(_v2() | {"state": {"dir": "/srv/state"}}).state
        self.assertEqual(Path("/tmp/clixz-state"), state.dir)

    def test_state_and_komodo_are_known_sections(self) -> None:
        raw = _v2() | {"state": {"dir": "/var/lib/clixz"}, "komodo": {"server": "boxyz"}}
        self.assertEqual([], validate_config(raw))


class KomodoTests(unittest.TestCase):
    def test_without_a_section_the_komodo_step_is_off(self) -> None:
        self.assertFalse(parse_config(_v2()).komodo.enabled)

    def test_a_section_without_credentials_uses_the_default_file(self) -> None:
        komodo = parse_config(_v2() | {"komodo": {"server": "boxyz"}}).komodo
        self.assertTrue(komodo.enabled)
        self.assertEqual(Path("/etc/clixz/komodo.yaml"), komodo.credentials)
        self.assertEqual("boxyz", komodo.server)
        self.assertEqual("komodo-core", komodo.container)
        self.assertEqual(9120, komodo.port)
        self.assertEqual("/services", komodo.run_root)

    def test_every_key_can_be_set(self) -> None:
        komodo = parse_config(_v2() | {"komodo": {
            "credentials": "/root/k.yaml", "container": "core", "port": 9000,
            "run_root": "/stacks"}}).komodo
        self.assertEqual(Path("/root/k.yaml"), komodo.credentials)
        self.assertEqual(("core", 9000, "/stacks"), (komodo.container, komodo.port, komodo.run_root))
        self.assertIsNone(komodo.server)

    def test_a_v1_komodo_principal_is_reported_with_its_migration_hint(self) -> None:
        issues = validate_config(_v2() | {"komodo": {"name": "boxyz_komodo", "kind": "group"}})
        self.assertTrue(any("komodo.name" in i and "DAC_OVERRIDE" in i for i in issues), issues)

    def test_a_non_mapping_section_is_reported(self) -> None:
        self.assertTrue(any("komodo" in i for i in validate_config(_v2() | {"komodo": "yes"})))


class SnapshotRetiredTests(unittest.TestCase):
    def test_npm_snapshot_is_reported_as_retired(self) -> None:
        issues = validate_config(_v2() | {"npm": {"database": "/x.sqlite", "snapshot": "/y.json"}})
        self.assertTrue(any("npm.snapshot" in i and "2.3" in i for i in issues), issues)


class MigrateTests(unittest.TestCase):
    def test_carries_identity_forward(self) -> None:
        out = migrate_raw(_v1())
        self.assertEqual("/srv/docker", out["root_dir"])
        self.assertIn("apps", out["categories"])
        self.assertEqual("/srv/docker/apps/api/data/manifest.json", out["api"]["manifest"])

    def test_drops_acl_sections_entirely(self) -> None:
        out = migrate_raw(_v1())
        self.assertNotIn("settings", out)
        self.assertNotIn("dev", out)
        self.assertNotIn("repos", out)

    def test_env_owner_is_forced_regardless_of_the_old_value(self) -> None:
        raw = _v1()
        raw["rules"]["env_file"]["owner"] = "svc_apps:svc_apps"
        self.assertEqual("root:root", migrate_raw(raw)["rules"]["env"]["owner"])

    def test_result_validates_cleanly(self) -> None:
        self.assertEqual([], validate_config(migrate_raw(_v1())))
