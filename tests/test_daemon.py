"""The package installs and keeps its own systemd units."""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clixz import daemon
from clixz.config import parse_config


def _config(base: Path) -> object:
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CLIXZ_STATE_DIR", None)
        return parse_config({
            "root_dir": "/srv/docker",
            "categories": {"network": {"user": "svc_network", "group": "svc_network"},
                           "apps": {"user": "svc_apps", "group": "svc_apps"},
                           "ia": {"user": "svc_ia", "group": "svc_ia"}},
            "api": {"manifest": str(base / "etc" / "manifest.json")},
            "state": {"dir": str(base / "state")},
        })


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.units = daemon.render_units(_config(self.base))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_every_unit_is_rendered(self) -> None:
        self.assertEqual(set(daemon.UNITS), set(self.units))

    def test_no_placeholder_is_left(self) -> None:
        for name, text in self.units.items():
            self.assertIsNone(re.search(r"@[A-Z_]+@", text), name)

    def test_the_gateway_reads_every_category(self) -> None:
        lines = [line for line in self.units["clixz-mcpd.service"].splitlines()
                 if line.startswith("SupplementaryGroups=")]
        self.assertEqual(["SupplementaryGroups=svc_apps svc_ia svc_network"], lines)

    def test_the_gateway_restarts_whenever_it_exits(self) -> None:
        self.assertIn("Restart=always", self.units["clixz-mcpd.service"])

    def test_the_applier_writes_only_the_tree_the_state_the_manifest_and_ignore(self) -> None:
        # ignore.yaml is the one file of /etc/clixz an (ignore) plan writes;
        # config.yaml and lint.yaml stay read-only.
        lines = [line for line in self.units["clixz-apply@.service"].splitlines()
                 if line.startswith("ReadWritePaths=")]
        self.assertEqual([f"ReadWritePaths=/srv/docker {self.base / 'state'} "
                          f"-{self.base / 'etc' / 'manifest.json'} -/etc/clixz/ignore.yaml"],
                         lines)

    def test_the_applier_socket_is_only_for_the_gateway(self) -> None:
        socket_unit = self.units["clixz-apply.socket"]
        for line in ("SocketGroup=svc_mcprun", "SocketMode=0660", "Accept=yes"):
            self.assertIn(line, socket_unit)


    def test_the_inspector_socket_is_only_for_the_gateway(self) -> None:
        socket_unit = self.units["clixz-inspect.socket"]
        for line in ("ListenStream=/run/clixz-inspect.sock", "SocketGroup=svc_mcprun",
                     "SocketMode=0660", "Accept=yes"):
            self.assertIn(line, socket_unit)

    def test_the_inspector_holds_the_docker_group_and_nothing_else(self) -> None:
        # The docker socket is root whatever else is removed: no capability, no
        # writable path, no network, and not root's own files (dynamic account).
        lines = self.units["clixz-inspect@.service"].splitlines()
        for line in ("DynamicUser=yes", "SupplementaryGroups=docker", "CapabilityBoundingSet=",
                     "NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateNetwork=yes",
                     "RestrictAddressFamilies=AF_UNIX"):
            self.assertIn(line, lines)
        self.assertFalse([line for line in lines if line.startswith(("User=", "ReadWritePaths="))])


class InstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.unit_dir = self.base / "systemd"
        self.unit_dir.mkdir()
        self.config = _config(self.base)
        for name, value in (("user_exists", True), ("mcpd_stale", False)):
            patcher = mock.patch.object(daemon, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _install(self) -> list[list[str]]:
        return daemon.install(self.config, unit_dir=self.unit_dir, dry_run=True)

    def _write_current_units(self) -> None:
        for name, text in daemon.render_units(self.config).items():
            (self.unit_dir / name).write_text(text, encoding="utf-8")

    def test_a_first_install_writes_and_starts_everything(self) -> None:
        commands = self._install()
        written = [c[1] for c in commands if c[0] == "write_file"]
        for name in daemon.UNITS:
            self.assertIn(str(self.unit_dir / name), written)
        self.assertIn(["systemctl", "daemon-reload"], commands)
        self.assertIn(["systemctl", "enable", "--now", "clixz-mcpd.service", "clixz-apply.socket",
                       "clixz-inspect.socket"], commands)

    def test_the_account_is_created_only_when_missing(self) -> None:
        self.assertNotIn("useradd", [c[0] for c in self._install()])
        with mock.patch.object(daemon, "user_exists", return_value=False):
            self.assertIn("useradd", [c[0] for c in self._install()])

    def test_the_state_directory_is_shared_and_the_plans_are_roots(self) -> None:
        commands = self._install()
        state, plans = str(self.base / "state"), str(self.base / "state" / "plans")
        self.assertIn(["chmod", "2775", state], commands)
        self.assertIn(["chmod", "700", plans], commands)
        self.assertIn(["chown", "root:root", plans], commands)

    def test_an_up_to_date_install_changes_nothing_and_starts_nothing(self) -> None:
        self._write_current_units()
        commands = self._install()
        self.assertNotIn("write_file", [c[0] for c in commands
                                        if c[-1].startswith(str(self.unit_dir))])
        self.assertNotIn(["systemctl", "daemon-reload"], commands)
        self.assertFalse([c for c in commands if "--now" in c])
        self.assertNotIn(daemon.RESTART_MCPD, commands)

    def test_a_changed_gateway_unit_is_reloaded_and_restarted_if_running(self) -> None:
        self._write_current_units()
        (self.unit_dir / "clixz-mcpd.service").write_text("old", encoding="utf-8")
        commands = self._install()
        self.assertIn(["systemctl", "daemon-reload"], commands)
        self.assertIn(daemon.RESTART_MCPD, commands)
        self.assertEqual(["systemctl", "try-restart", "clixz-mcpd.service"], daemon.RESTART_MCPD)

    def test_a_gateway_on_old_code_is_restarted(self) -> None:
        self._write_current_units()
        with mock.patch.object(daemon, "mcpd_stale", return_value=True):
            self.assertIn(daemon.RESTART_MCPD, self._install())

    def test_an_upgrade_from_2_2_starts_the_new_socket_only(self) -> None:
        self._write_current_units()
        (self.unit_dir / "clixz-apply.socket").unlink()
        (self.unit_dir / "clixz-apply@.service").unlink()
        commands = self._install()
        self.assertIn(["systemctl", "enable", "--now", "clixz-apply.socket"], commands)

    def test_an_upgrade_from_2_5_starts_the_inspector_socket_only(self) -> None:
        self._write_current_units()
        for name in ("clixz-inspect.socket", "clixz-inspect@.service"):
            (self.unit_dir / name).unlink()
        commands = self._install()
        self.assertIn(["systemctl", "enable", "--now", "clixz-inspect.socket"], commands)
        self.assertNotIn(daemon.RESTART_MCPD, commands)

    def test_retired_units_and_the_snapshot_go(self) -> None:
        (self.unit_dir / "clixz-snapshot.timer").write_text("x", encoding="utf-8")
        commands = self._install()
        self.assertIn(["systemctl", "disable", "--now", "clixz-snapshot.timer"], commands)
        self.assertIn(["rm", "-f", str(self.unit_dir / "clixz-snapshot.timer")], commands)


class DriftTests(unittest.TestCase):
    def test_missing_differs_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = _config(base)
            self.assertEqual({"missing"}, set(daemon.unit_drift(config, base).values()))
            for name, text in daemon.render_units(config).items():
                (base / name).write_text(text, encoding="utf-8")
            self.assertEqual({"ok"}, set(daemon.unit_drift(config, base).values()))
            (base / "clixz-apply.socket").write_text("changed", encoding="utf-8")
            self.assertEqual("differs", daemon.unit_drift(config, base)["clixz-apply.socket"])


class OutOfDateTests(unittest.TestCase):
    """What `clixz upgrade` reports when there is no newer release to install."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.config = _config(self.base)
        for name, text in daemon.render_units(self.config).items():
            (self.base / name).write_text(text, encoding="utf-8")
        patcher = mock.patch.object(daemon, "mcpd_stale", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_units_as_rendered_are_up_to_date(self) -> None:
        self.assertEqual([], daemon.out_of_date(self.config, self.base))

    def test_a_unit_edited_by_hand_is_reported(self) -> None:
        (self.base / "clixz-apply.socket").write_text("changed", encoding="utf-8")
        self.assertEqual(["clixz-apply.socket"], daemon.out_of_date(self.config, self.base))

    def test_a_missing_unit_is_reported(self) -> None:
        (self.base / "clixz-inspect@.service").unlink()
        self.assertEqual(["clixz-inspect@.service"], daemon.out_of_date(self.config, self.base))

    def test_a_gateway_running_older_code_is_reported(self) -> None:
        with mock.patch.object(daemon, "mcpd_stale", return_value=True):
            self.assertEqual([daemon.MCPD_UNIT], daemon.out_of_date(self.config, self.base))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
