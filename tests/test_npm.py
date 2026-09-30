"""Cross-checking what the reverse proxy publishes against what the tree declares."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from clixz.npm import NpmUnavailable, ProxyHost, cross_check, read_proxy_hosts

_ROWS = [
    (["vault.coxyz.fr"], 1, 0, "bitwarden", 80),
    (["mcp.coxyz.fr"], 1, 0, "mcp", 8000),
    (["portainer.coxyz.fr"], 1, 0, "portainer", 9000),
    (["*.coxyz.fr"], 1, 0, "web", 80),
    (["server.coxyz.fr"], 1, 0, "192.168.1.6", 25565),
    (["code.coxyz.fr"], 0, 0, "code-server", 8443),
]


def _database(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        "create table proxy_host (domain_names text, enabled int, "
        "access_list_id int, forward_host text, forward_port int, is_deleted int)"
    )
    conn.executemany(
        "insert into proxy_host values (?,?,?,?,?,0)",
        [(json.dumps(d), e, a, h, p) for d, e, a, h, p in _ROWS],
    )
    conn.commit()
    conn.close()


class ReadTests(unittest.TestCase):
    def test_reads_and_decodes_every_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "database.sqlite"
            _database(path)
            hosts = read_proxy_hosts(path)
            self.assertEqual(6, len(hosts))
            self.assertEqual(["vault.coxyz.fr"], hosts[0].domains)
            self.assertEqual("bitwarden:80", hosts[0].target)
            self.assertFalse(hosts[-1].enabled)

    def test_missing_database_is_reported_not_raised_as_a_crash(self) -> None:
        with self.assertRaises(NpmUnavailable):
            read_proxy_hosts(Path("/nonexistent/database.sqlite"))


class CrossCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hosts = [ProxyHost(d, bool(e), a, h, p) for d, e, a, h, p in _ROWS]
        self.declared = {"apps/bitwarden": "https://vault.coxyz.fr"}
        self.containers = {"bitwarden", "mcp", "npm"}

    def _messages(self, level: str) -> list[str]:
        report = cross_check(self.hosts, self.declared, self.containers)
        return [m for lvl, m in report.findings if lvl == level]

    def test_declared_and_published_host_is_silent(self) -> None:
        self.assertEqual([], [m for m in self._messages("warn") if "vault" in m])

    def test_published_but_undeclared_host_is_flagged(self) -> None:
        # This is the finding that would have surfaced mcp.coxyz.fr.
        self.assertTrue(any("mcp.coxyz.fr" in m and "no service.yaml" in m
                            for m in self._messages("warn")))

    def test_dead_target_is_flagged_because_it_is_still_enabled(self) -> None:
        self.assertTrue(any("portainer" in m and "no such container" in m
                            for m in self._messages("warn")))

    def test_wildcard_is_flagged(self) -> None:
        self.assertTrue(any("wildcard" in m for m in self._messages("warn")))

    def test_ip_target_is_reported_as_a_doorway_to_another_machine(self) -> None:
        self.assertTrue(any("another machine" in m for m in self._messages("info")))

    def test_missing_access_list_is_reported(self) -> None:
        self.assertTrue(any("no access list" in m for m in self._messages("info")))

    def test_declared_but_unpublished_host_is_flagged(self) -> None:
        self.declared["apps/atuin"] = "https://atuin.coxyz.fr"
        self.assertTrue(any("atuin" in m and "does not publish" in m
                            for m in self._messages("warn")))

    def test_disabled_host_raises_nothing(self) -> None:
        self.assertEqual([], [m for m in self._messages("warn") if "code.coxyz.fr" in m])

    def test_docker_absent_skips_the_dead_target_check(self) -> None:
        report = cross_check(self.hosts, self.declared, None)
        self.assertEqual([], [m for _, m in report.findings if "no such container" in m])
