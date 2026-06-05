"""Tests for the dev compose editor and ACL command builders (pure logic)."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from coxyz.dev import (
    MARKER_BEGIN,
    MARKER_END,
    acl_disable_cmds,
    acl_enable_cmds,
    add_service,
    mount_targets,
    read_enabled,
    remove_service,
)

ROOT = Path("/srv/docker")
MOUNT = "/workspace/services"

# A hand-maintained compose with comments that MUST survive every edit.
COMPOSE = """\
services:
  code-boxyz:
    image: lscr.io/linuxserver/code-server:latest

    cap_add:
      - DAC_OVERRIDE   # keep this comment

    volumes:
      # Config code-server
      - /srv/docker/apps/code-boxyz/config:/config

      # Repos:
      - /opt/repos:/workspace/repos

    networks:
      - boxyz_network

networks:
  boxyz_network:
    external: true
"""


class ComposeEditorTests(unittest.TestCase):
    def test_no_block_means_nothing_enabled(self) -> None:
        self.assertEqual([], read_enabled(COMPOSE, ROOT, MOUNT))

    def test_add_inserts_config_and_data_mounts(self) -> None:
        out = add_service(COMPOSE, "apps", "nginx", ROOT, MOUNT)
        self.assertIn(MARKER_BEGIN, out)
        self.assertIn(MARKER_END, out)
        self.assertIn(
            "      - /srv/docker/apps/nginx/config:/workspace/services/apps/nginx/config", out
        )
        self.assertIn(
            "      - /srv/docker/apps/nginx/data:/workspace/services/apps/nginx/data", out
        )
        self.assertEqual([("apps", "nginx")], read_enabled(out, ROOT, MOUNT))

    def test_edit_preserves_comments_and_other_volumes(self) -> None:
        out = add_service(COMPOSE, "apps", "nginx", ROOT, MOUNT)
        self.assertIn("# keep this comment", out)
        self.assertIn("# Config code-server", out)
        self.assertIn("- /srv/docker/apps/code-boxyz/config:/config", out)
        self.assertIn("- /opt/repos:/workspace/repos", out)
        # The result is still valid YAML with the two managed mounts present.
        doc = yaml.safe_load(out)
        vols = doc["services"]["code-boxyz"]["volumes"]
        self.assertIn("/srv/docker/apps/nginx/config:/workspace/services/apps/nginx/config", vols)

    def test_block_lands_inside_the_volumes_list(self) -> None:
        out = add_service(COMPOSE, "apps", "nginx", ROOT, MOUNT).splitlines()
        vi = out.index("    volumes:")
        ni = out.index("    networks:")
        begin = next(i for i, l in enumerate(out) if l.strip() == MARKER_BEGIN)
        self.assertTrue(vi < begin < ni, "managed block must sit within the volumes block")

    def test_add_is_sorted_and_idempotent(self) -> None:
        out = add_service(COMPOSE, "network", "pihole", ROOT, MOUNT)
        out = add_service(out, "apps", "nginx", ROOT, MOUNT)
        self.assertEqual([("apps", "nginx"), ("network", "pihole")], read_enabled(out, ROOT, MOUNT))
        again = add_service(out, "apps", "nginx", ROOT, MOUNT)  # re-add existing
        self.assertEqual(out, again, "re-adding an enabled service must be a no-op")

    def test_remove_one_keeps_the_other(self) -> None:
        out = add_service(COMPOSE, "apps", "nginx", ROOT, MOUNT)
        out = add_service(out, "network", "pihole", ROOT, MOUNT)
        out = remove_service(out, "apps", "nginx", ROOT, MOUNT)
        self.assertEqual([("network", "pihole")], read_enabled(out, ROOT, MOUNT))

    def test_removing_last_service_drops_the_block(self) -> None:
        out = add_service(COMPOSE, "apps", "nginx", ROOT, MOUNT)
        out = remove_service(out, "apps", "nginx", ROOT, MOUNT)
        self.assertNotIn(MARKER_BEGIN, out)
        self.assertEqual([], read_enabled(out, ROOT, MOUNT))
        # Removing everything returns to the original file byte-for-byte.
        self.assertEqual(COMPOSE, out)

    def test_final_newline_preserved(self) -> None:
        self.assertTrue(add_service(COMPOSE, "apps", "nginx", ROOT, MOUNT).endswith("\n"))


class AclCommandTests(unittest.TestCase):
    def test_enable_group_uses_capital_x_and_default_acl(self) -> None:
        cmds = acl_enable_cmds([Path("/srv/docker/apps/nginx/config")], "group", "boxyz_dev", "rwx")
        self.assertEqual(
            [
                ["setfacl", "-R", "-m", "g:boxyz_dev:rwX", "/srv/docker/apps/nginx/config"],
                ["setfacl", "-dR", "-m", "g:boxyz_dev:rwX", "/srv/docker/apps/nginx/config"],
            ],
            cmds,
        )

    def test_enable_user_principal_uses_u_prefix(self) -> None:
        # The live config models boxyz_dev as a USER, so the qualifier must be u:.
        cmds = acl_enable_cmds([Path("/x")], "user", "boxyz_dev", "rwx")
        self.assertEqual("u:boxyz_dev:rwX", cmds[0][3])

    def test_enable_token_normalizes_perms(self) -> None:
        # Compact setfacl form (no dashes); execute rendered as capital X.
        cmds = acl_enable_cmds([Path("/x")], "group", "g", "rx")
        self.assertEqual("g:g:rX", cmds[0][3])

    def test_disable_removes_only_that_principal(self) -> None:
        cmds = acl_disable_cmds([Path("/srv/docker/apps/nginx/data")], "user", "boxyz_dev")
        self.assertEqual(
            [
                ["setfacl", "-R", "-x", "u:boxyz_dev", "/srv/docker/apps/nginx/data"],
                ["setfacl", "-dR", "-x", "u:boxyz_dev", "/srv/docker/apps/nginx/data"],
            ],
            cmds,
        )

    def test_mount_targets(self) -> None:
        self.assertEqual(
            ["/workspace/services/apps/nginx/config", "/workspace/services/apps/nginx/data"],
            mount_targets("apps", "nginx", "/workspace/services"),
        )


if __name__ == "__main__":
    unittest.main()
