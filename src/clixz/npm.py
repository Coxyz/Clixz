"""What Nginx Proxy Manager actually publishes, versus what the tree declares.

The audit of 2026-08-29 found 24 proxy hosts, 20 of them enabled, where the
``service.yaml`` descriptors declared 9 public URLs — and no access list on any
of them. Two of the undeclared hosts were a direct path from the internet to
host root. Nothing in the system noticed, because every check looked at files
and the exposure lived in a database.

So this module reads that database. It is read-only, it needs root, and it
degrades to a warning when it cannot read — an unreadable database is a fact to
report, not a reason to fail.

Until 2.3 a timer copied the hosts every 15 minutes into a world-readable
snapshot for the unprivileged gateway, which then answered with data up to a
quarter of an hour old. Now the gateway relays ``exposed`` to ``clixz-apply``,
a root process started for that one request, which reads the database at the
moment of the question. Nothing hands the gateway the database itself.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import Config
from .meta import declared_urls


@dataclass(frozen=True)
class ProxyHost:
    domains: list[str]
    enabled: bool
    access_list_id: int
    forward_host: str
    forward_port: int

    @property
    def target(self) -> str:
        return f"{self.forward_host}:{self.forward_port}"


class NpmUnavailable(RuntimeError):
    """The database could not be read (absent, or unreadable without root)."""


def read_proxy_hosts(database: Path) -> list[ProxyHost]:
    """Read every proxy host. Raises :class:`NpmUnavailable` if it cannot."""
    if not database.is_file():
        # Distinguish "absent" from "you are not root": the NPM data directory
        # is root:root 0750, so an unprivileged stat() fails exactly the same
        # way a missing file does, and reporting the wrong one sends the reader
        # looking for a path that is right there.
        if not os.access(database.parent, os.X_OK):
            raise NpmUnavailable(
                f"cannot read {database} — {database.parent} is not traversable. "
                "Re-run with sudo."
            )
        raise NpmUnavailable(f"no such database: {database}")
    try:
        # Read-only URI, so a live NPM is never disturbed by the audit.
        conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise NpmUnavailable(f"cannot open {database}: {exc}. Try with sudo.") from exc
    try:
        rows = conn.execute(
            "select domain_names, enabled, access_list_id, forward_host, forward_port "
            "from proxy_host where is_deleted = 0"
        ).fetchall()
    except sqlite3.Error as exc:
        raise NpmUnavailable(f"cannot query {database}: {exc}") from exc
    finally:
        conn.close()

    hosts: list[ProxyHost] = []
    for domains_raw, enabled, access_list_id, forward_host, forward_port in rows:
        try:
            domains = json.loads(domains_raw) if isinstance(domains_raw, str) else []
        except ValueError:
            domains = [str(domains_raw)]
        hosts.append(ProxyHost(
            domains=[str(d) for d in domains],
            enabled=bool(enabled),
            access_list_id=int(access_list_id or 0),
            forward_host=str(forward_host or ""),
            forward_port=int(forward_port or 0),
        ))
    return hosts


def running_containers() -> set[str] | None:
    """Names of existing containers, or None when docker cannot be queried."""
    if shutil.which("docker") is None:
        return None
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    return {line.strip() for line in out.splitlines() if line.strip()}


@dataclass
class ExposureReport:
    hosts: list[ProxyHost] = field(default_factory=list)
    # (level, message) — level is "error" | "warn" | "info"
    findings: list[tuple[str, str]] = field(default_factory=list)

    @property
    def enabled_hosts(self) -> list[ProxyHost]:
        return [h for h in self.hosts if h.enabled]


def _hostnames(url: str) -> str:
    parsed = urlparse(url if "//" in url else f"//{url}")
    return (parsed.hostname or "").lower()


def cross_check(
    hosts: list[ProxyHost],
    declared_urls: dict[str, str],
    containers: set[str] | None = None,
) -> ExposureReport:
    """Compare what NPM publishes against what the service descriptors declare.

    ``declared_urls`` maps ``category/service`` to the ``url:`` in its
    ``service.yaml``. ``containers`` is used to spot a proxy host pointing at a
    target that does not exist — harmless today (it returns 502), but it is
    *enabled*, so the day a container of that name appears it is public without
    anyone deciding so.
    """
    report = ExposureReport(hosts=hosts)
    declared = {_hostnames(u): svc for svc, u in declared_urls.items() if u}

    for host in hosts:
        if not host.enabled:
            continue
        for domain in host.domains:
            name = domain.lower()
            if name.startswith("*."):
                report.findings.append((
                    "warn",
                    f"{domain} is a wildcard: it reserves every subdomain not "
                    f"explicitly listed, and forwards them to {host.target}",
                ))
                continue
            if name not in declared:
                report.findings.append((
                    "warn",
                    f"{domain} → {host.target} is published but no service.yaml "
                    "declares it",
                ))
        if host.access_list_id == 0:
            for domain in host.domains:
                report.findings.append((
                    "info", f"{domain} has no access list in front of it",
                ))
        if containers is not None and host.forward_host and host.forward_host not in containers:
            # An IP target is a different machine, not a dead container.
            if not host.forward_host.replace(".", "").isdigit():
                report.findings.append((
                    "warn",
                    f"{', '.join(host.domains)} → {host.target}: no such container. "
                    "The entry is dead but enabled — it becomes live the day a "
                    "container of that name exists.",
                ))
        if host.forward_host.replace(".", "").isdigit():
            report.findings.append((
                "info",
                f"{', '.join(host.domains)} → {host.target} points at a host address, "
                "not a container: this proxy is a doorway to another machine",
            ))

    published = {
        d.lower() for h in hosts if h.enabled for d in h.domains if not d.startswith("*.")
    }
    for hostname, service in sorted(declared.items()):
        if hostname not in published:
            report.findings.append((
                "warn", f"{service} declares {hostname} but NPM does not publish it",
            ))
    return report


def exposure_payload(config: Config) -> dict[str, Any]:
    """What ``clixz exposed --json`` prints, read live. Never raises."""
    database = config.npm.database
    if database is None:
        return {"available": False,
                "reason": "npm.database is disabled in the config — nothing to cross-check"}
    try:
        hosts = read_proxy_hosts(database)
    except NpmUnavailable as exc:
        return {"available": False, "reason": str(exc)}
    report = cross_check(hosts, declared_urls(config), running_containers())
    return {
        "available": True,
        "source": "database",
        "hosts": [
            {"domains": h.domains, "enabled": h.enabled,
             "access_list_id": h.access_list_id, "target": h.target}
            for h in report.hosts
        ],
        "findings": [{"level": lvl, "message": msg} for lvl, msg in report.findings],
        "summary": {"total": len(report.hosts), "enabled": len(report.enabled_hosts)},
    }

