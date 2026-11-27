"""clixz-inspect: what the MCP may read of the running containers, and what it may not."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from clixz import inspectd, runtime
from clixz.config import parse_config, validate_config
from clixz.docker_api import DockerClient, NotFound, demux
from clixz.hoststat import host_status

SECRET = "hunter2-very-secret-passphrase"
TOKEN = "s3cr3t-cmd-token"

_CONFIG = {
    "root_dir": "/srv/docker",
    "categories": {"apps": {"user": "svc_apps", "group": "svc_apps"},
                   "infra": {"user": "svc_infra", "group": "svc_infra"}},
    "komodo": {"run_root": "/services"},
    "docker": {"logs": ["apps/atuin"]},
}


def _labels(path: str) -> dict:
    return {"com.docker.compose.project": "atuin", "com.docker.compose.service": "atuin",
            "com.docker.compose.project.working_dir": path,
            "traefik.http.middlewares.auth.basicauth.users": "admin:$apr1$hash"}


def _inspect(name: str, wd: str) -> dict:
    return {
        "Id": "a" * 64, "Name": f"/{name}", "Image": "sha256:" + "b" * 64, "RestartCount": 3,
        "Created": "2026-11-27T10:00:00Z",
        "State": {"Status": "running", "Running": True, "OOMKilled": False, "ExitCode": 0,
                  "Error": "", "Health": {"Status": "unhealthy", "FailingStreak": 2, "Log": [
                      {"Start": "s", "End": "e", "ExitCode": 1, "Output": f"curl: auth {SECRET} failed"}]}},
        "Config": {"Image": "atuin:18", "User": "1000:1000", "Tty": False,
                   "Env": [f"ATUIN_DB_PASSWORD={SECRET}", "TZ=Europe/Paris", "DEBUG=1"],
                   "Cmd": ["server", "--token", TOKEN], "Entrypoint": ["atuin"],
                   "Labels": _labels(wd),
                   "Healthcheck": {"Test": ["CMD", f"curl -H 'Authorization: Bearer {TOKEN}' "
                                                   f"-u x:{SECRET}"]}},
        "Args": ["--token", TOKEN],
        "HostConfig": {"Privileged": False, "CapAdd": ["CHOWN"], "CapDrop": ["ALL"],
                       "SecurityOpt": ["no-new-privileges:true"], "GroupAdd": ["1005"],
                       "Devices": [{"PathOnHost": "/dev/ttyUSB0", "PathInContainer": "/dev/ttyUSB0"}],
                       "NetworkMode": "boxyz_network", "Memory": 268435456, "PidsLimit": 100,
                       "RestartPolicy": {"Name": "unless-stopped"},
                       "LogConfig": {"Type": "splunk", "Config": {"max-size": "10m",
                                                                  "splunk-token": TOKEN}}},
        "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock", "RW": True},
                   {"Type": "bind", "Source": "/srv/docker/apps/atuin/data", "Destination": "/data",
                    "RW": True}],
        "NetworkSettings": {"Networks": {"boxyz_network": {"IPAddress": "172.20.0.5"}},
                            "Ports": {"8888/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8888"}]}},
    }


def _frame(stream: int, text: str) -> bytes:
    data = text.encode()
    return struct.pack(">BxxxI", stream, len(data)) + data


class FakeDocker(DockerClient):
    """dockerd as the tests want it; records every path asked for."""

    def __init__(self, logs: bytes = b"") -> None:
        super().__init__("/nonexistent")
        self.asked: list[str] = []
        self._logs = logs
        self.containers_ = {
            "atuin": _inspect("atuin", "/services/apps/atuin"),
            "bitwarden": _inspect("bitwarden", "/services/apps/bitwarden"),
            "stray": _inspect("stray", "/home/someone/compose"),
        }

    def containers(self) -> list[dict]:
        self.asked.append("containers")
        return [{"Id": c["Id"], "Names": [c["Name"]], "Image": c["Config"]["Image"],
                 "State": "running", "Status": "Up 2 hours (unhealthy)",
                 "Ports": [{"IP": "127.0.0.1", "PrivatePort": 8888, "PublicPort": 8888, "Type": "tcp"}],
                 "Labels": c["Config"]["Labels"]} for c in self.containers_.values()]

    def inspect(self, name: str) -> dict:
        self.asked.append(f"inspect {name}")
        if name not in self.containers_:
            raise NotFound("no such container")
        return self.containers_[name]

    def stats(self, name: str) -> dict:
        self.asked.append(f"stats {name}")
        return {"cpu_stats": {"cpu_usage": {"total_usage": 300}, "system_cpu_usage": 2000, "online_cpus": 4},
                "precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000},
                "memory_stats": {"usage": 150, "limit": 1000, "stats": {"inactive_file": 50}},
                "pids_stats": {"current": 7},
                "networks": {"eth0": {"rx_bytes": 10, "tx_bytes": 20}},
                "blkio_stats": {"io_service_bytes_recursive": [{"op": "read", "value": 5},
                                                               {"op": "write", "value": 6}]}}

    def logs(self, name: str, *, tail: int, since: int | None = None) -> bytes:
        self.asked.append(f"logs {name} {tail} {since is not None}")
        return self._logs

    def info(self) -> dict:
        return {"ServerVersion": "29.0", "Containers": 3, "Swarm": {"LocalNodeState": "active"},
                "RegistryConfig": {"secret": "x"}, "HttpProxy": "http://user:pw@proxy"}


class InspectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = parse_config(_CONFIG)
        self.docker = FakeDocker()

    def ask(self, docker: FakeDocker | None = None, **req) -> dict:
        return inspectd.handle(json.dumps(req).encode(), self.config, docker or self.docker)

    # ── what is refused ──────────────────────────────────────────────────

    def test_only_the_closed_set_of_requests(self) -> None:
        for cmd in ("exec", "restart", "start", "kill", None, 1, ["containers"]):
            answer = self.ask(cmd=cmd)
            self.assertFalse(answer["ok"], cmd)
            self.assertIn("not allowed", answer["error"])

    def test_a_container_name_cannot_reach_another_path(self) -> None:
        for name in ("../../images/json", "atuin/../x", "atuin?all=1", "", " atuin", "-atuin",
                     "a" * 129, 42, None, ["atuin"]):
            answer = self.ask(cmd="container", name=name)
            self.assertFalse(answer["ok"], name)
            self.assertIn("invalid container name", answer["error"])
        self.assertEqual([], self.docker.asked)

    def test_tail_and_since_are_bounded_whole_numbers(self) -> None:
        for key, value in (("tail", 0), ("tail", 1001), ("tail", True), ("tail", "10"),
                           ("since", 7 * 86400 + 1), ("since", -1), ("since", 1.5)):
            answer = self.ask(cmd="container-logs", name="atuin", **{key: value})
            self.assertFalse(answer["ok"], (key, value))
        self.assertEqual([], [a for a in self.docker.asked if a.startswith("logs")])

    def test_logs_of_a_service_not_listed_are_refused_without_reading_them(self) -> None:
        answer = self.ask(cmd="container-logs", name="bitwarden")
        self.assertFalse(answer["ok"])
        self.assertIn("apps/bitwarden", answer["error"])
        self.assertIn("/etc/clixz/config.yaml", answer["error"])
        self.assertNotIn("logs bitwarden", " ".join(self.docker.asked))

    def test_logs_of_a_container_outside_the_tree_are_refused(self) -> None:
        answer = self.ask(cmd="container-logs", name="stray")
        self.assertFalse(answer["ok"])
        self.assertIn("no clixz service", answer["error"])

    def test_an_unknown_container_is_an_answer_not_a_crash(self) -> None:
        answer = self.ask(cmd="container", name="nope")
        self.assertEqual({"ok": False, "error": "no such container: 'nope'"}, answer)

    def test_an_oversized_or_malformed_request(self) -> None:
        self.assertFalse(inspectd.handle(b"x" * 5000, self.config, self.docker)["ok"])
        self.assertFalse(inspectd.handle(b"[1]", self.config, self.docker)["ok"])
        self.assertFalse(inspectd.handle(b"{", self.config, self.docker)["ok"])

    # ── what never leaves ────────────────────────────────────────────────

    def test_no_environment_value_no_command_no_foreign_label_value(self) -> None:
        text = json.dumps(self.ask(cmd="container", name="bitwarden"))
        for secret in (SECRET, TOKEN, "Europe/Paris", "$apr1$hash"):
            self.assertNotIn(secret, text)
        detail = self.ask(cmd="container", name="bitwarden")["container"]
        self.assertEqual(["ATUIN_DB_PASSWORD", "DEBUG", "TZ"], detail["environment_keys"])
        self.assertEqual(["traefik.http.middlewares.auth.basicauth.users"], detail["other_label_keys"])
        self.assertIsNone(detail["healthcheck_test"])
        opened = self.ask(cmd="container", name="atuin")["container"]["healthcheck_test"]
        self.assertEqual("CMD", opened[0])
        self.assertNotIn(TOKEN, opened[1])
        self.assertNotIn(SECRET, opened[1])
        self.assertEqual({"max-size": "10m", "splunk-token": "[masqué]"}, detail["logging"]["options"])

    def test_health_output_only_where_logs_are_allowed_and_masked(self) -> None:
        closed = self.ask(cmd="container", name="bitwarden")["container"]["state"]["health"]
        self.assertNotIn("output", closed["last_checks"][0])
        opened = self.ask(cmd="container", name="atuin")["container"]["state"]["health"]
        self.assertEqual("curl: auth [masqué:ATUIN_DB_PASSWORD] failed", opened["last_checks"][0]["output"])

    def test_docker_info_keeps_only_named_fields(self) -> None:
        info = self.ask(cmd="docker-info")["docker"]
        self.assertEqual(("29.0", "active"), (info["ServerVersion"], info["Swarm"]))
        self.assertNotIn("pw@proxy", json.dumps(info))

    # ── what is shown ────────────────────────────────────────────────────

    def test_the_audit_view(self) -> None:
        c = self.ask(cmd="container", name="atuin")["container"]
        self.assertEqual(("apps/atuin", True, 3), (c["service"], c["logs_allowed"],
                                                    c["state"]["restart_count"]))
        self.assertEqual((["CHOWN"], ["1005"], ["/dev/ttyUSB0:/dev/ttyUSB0"]),
                         (c["security"]["cap_add"], c["security"]["group_add"], c["security"]["devices"]))
        self.assertEqual([True, False], [m["sensitive"] for m in c["mounts"]])
        self.assertEqual(["127.0.0.1:8888->8888/tcp"], c["ports"])

    def test_the_list_maps_containers_to_services(self) -> None:
        items = {c["name"]: c for c in self.ask(cmd="containers")["containers"]}
        atuin = items["atuin"]
        self.assertEqual(("apps/atuin", True, "unhealthy"),
                         (atuin["service"], atuin["logs_allowed"], atuin["health"]))
        self.assertEqual((None, False), (items["stray"]["service"], items["stray"]["logs_allowed"]))
        self.assertEqual(["127.0.0.1:8888->8888/tcp"], items["atuin"]["ports"])

    def test_stats_of_one_and_of_every_running_container(self) -> None:
        one = self.ask(cmd="container-stats", name="atuin")["stats"]
        self.assertEqual([{"name": "atuin", "cpu_percent": 80.0, "memory_used": 100, "memory_limit": 1000,
                           "memory_percent": 10.0, "pids": 7, "net_rx_bytes": 10, "net_tx_bytes": 20,
                           "block_read_bytes": 5, "block_write_bytes": 6}], one)
        every = self.ask(cmd="container-stats")["stats"]
        self.assertEqual(["atuin", "bitwarden", "stray"], [s["name"] for s in every])

    def test_logs_are_demultiplexed_cleaned_masked(self) -> None:
        raw = (_frame(1, "2026-11-27T10:00:00Z started\n")
               + _frame(2, f"2026-11-27T10:00:01Z \x1b[31merror\x1b[0m db password={SECRET}\r\n")
               + _frame(1, "GET /?token=abc123 Authorization: Bearer "
                           "eyJhbGciOiJI.eyJzdWIiOiIx.c2lnbmF0dXJl\n"))
        answer = self.ask(FakeDocker(logs=raw), cmd="container-logs", name="atuin", tail=50, since=3600)
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(3, answer["count"])
        text = "\n".join(answer["lines"])
        for leaked in (SECRET, "abc123", "eyJhbGciOiJI", "\x1b", "\r"):
            self.assertNotIn(leaked, text)
        self.assertIn("error db password=[masqué:ATUIN_DB_PASSWORD]", text)

    def test_an_escape_between_key_and_value_does_not_hide_a_secret(self) -> None:
        raw = _frame(1, "\x1b[36mclient_secret\x1b[0m=Zq81notInEnv\n")
        answer = self.ask(FakeDocker(logs=raw), cmd="container-logs", name="atuin")
        self.assertEqual(["client_secret=[masqué]"], answer["lines"])


class RedactorTests(unittest.TestCase):
    def test_environment_values(self) -> None:
        r = runtime.Redactor(["API_KEY=abc", "SHORT=12", "LONG_PLAIN=abcdefgh", "EMPTY="])
        self.assertEqual("k=[masqué:API_KEY] v=12 w=[masqué:LONG_PLAIN]", r("k=abc v=12 w=abcdefgh"))

    def test_shapes(self) -> None:
        r = runtime.Redactor()
        cases = {
            "postgres://atuin:Pa55word@db:5432/atuin": "postgres://atuin:[masqué]@db:5432/atuin",
            'json {"password": "x9"}': 'json {"password": "[masqué]"}',
            "Authorization: Basic YWRtaW46cGFzcw==": "Authorization: Basic [masqué]",
            "key ghp_0123456789abcdefghijklmnopqrstuvwxyzAB end": "key [masqué:jeton] end",
        }
        for raw, expected in cases.items():
            self.assertEqual(expected, r(raw))

    def test_what_is_not_a_secret_stays(self) -> None:
        r = runtime.Redactor()
        for line in ("image sha256:" + "0123456789abcdef" * 4,
                     "File /usr/local/lib/python3.12/site-packages/nextcloud/apps/files/lib.py, line 12",
                     "token expired, renewing", "550e8400-e29b-41d4-a716-446655440000"):
            self.assertEqual(line, r(line))

    def test_a_private_key_block(self) -> None:
        text = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\nabc\n-----END RSA PRIVATE KEY-----\nb"
        self.assertEqual("a\n[masqué:clé privée]\nb", runtime.Redactor()(text))

    def test_a_long_line_costs_linear_time(self) -> None:
        # A service writes its own lines: one must not stall the reader (it did, n²).
        import time
        line = ("x" * 200_000) + " password=" + ("y" * 100_000)
        start = time.monotonic()
        out = runtime.Redactor(["A_SECRET=abcdefghij"])(line)
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertTrue(out.endswith("password=[masqué]"))

    def test_the_most_recent_lines_are_kept_within_the_bound(self) -> None:
        raw = "".join(f"line {i} " + "x" * 1000 + "\n" for i in range(400)).encode()
        view = runtime.logs_view(raw, tty=True, redact=runtime.Redactor())
        self.assertTrue(view["truncated"])
        self.assertTrue(view["lines"][-1].startswith("line 399 "))
        self.assertLessEqual(sum(len(x) + 1 for x in view["lines"]), runtime.MAX_LOG_BYTES)


class MappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = parse_config(_CONFIG)

    def test_komodo_and_host_working_directories(self) -> None:
        for wd, expected in (("/services/apps/atuin", "apps/atuin"),
                             ("/srv/docker/infra/komodo", "infra/komodo"),
                             ("/services/media/jellyfin", None), ("/services/apps", None),
                             ("/services/apps/atuin/sub", None), ("/servicesx/apps/atuin", None),
                             (None, None)):
            labels = {"com.docker.compose.project.working_dir": wd} if wd else {}
            self.assertEqual(expected, runtime.service_of(labels, self.config), wd)


class ConfigTests(unittest.TestCase):
    def test_malformed_entries_grant_nothing_and_are_reported(self) -> None:
        raw = {**_CONFIG, "docker": {"logs": ["apps/atuin", "apps", "../x/y", 3, "media/x"], "sockett": 1}}
        self.assertEqual(("apps/atuin", "media/x"), parse_config(raw).docker.logs)
        issues = validate_config(raw)
        self.assertTrue(any("docker.sockett" in i for i in issues))
        self.assertTrue(any("'apps'" in i for i in issues))
        self.assertTrue(any("'media/x' names an unknown category" in i for i in issues))

    def test_no_section_means_no_logs(self) -> None:
        raw = {k: v for k, v in _CONFIG.items() if k != "docker"}
        self.assertEqual((), parse_config(raw).docker.logs)
        self.assertEqual("/run/docker.sock", str(parse_config(raw).docker.socket))


class DemuxTests(unittest.TestCase):
    def test_frames_and_tty(self) -> None:
        self.assertEqual([("out", "a"), ("err", "b")], demux(_frame(1, "a") + _frame(2, "b"), tty=False))
        self.assertEqual([("out", "raw")], demux(b"raw", tty=True))


class HostStatusTests(unittest.TestCase):
    def test_read_from_proc_and_sys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            proc, thermal = base / "proc", base / "thermal"
            (proc / "pressure").mkdir(parents=True)
            (proc / "meminfo").write_text("MemTotal: 4000 kB\nMemAvailable: 1000 kB\n"
                                          "SwapTotal: 2000 kB\nSwapFree: 500 kB\n")
            (proc / "loadavg").write_text("1.5 2.0 3.25 2/300 999\n")
            (proc / "uptime").write_text("3600.42 100.0\n")
            (proc / "pressure" / "memory").write_text(
                "some avg10=0.74 avg60=6.98 avg300=14.92 total=1\n"
                "full avg10=0.27 avg60=4.72 avg300=10.44 total=2\n")
            (thermal / "thermal_zone0").mkdir(parents=True)
            (thermal / "thermal_zone0" / "temp").write_text("50147\n")
            (thermal / "thermal_zone0" / "type").write_text("cpu-thermal\n")
            status = host_status(base, proc=proc, thermal=thermal)
        self.assertEqual(3600, status["uptime_seconds"])
        self.assertEqual([1.5, 2.0, 3.25], status["load"])
        self.assertEqual(1024 * 1000, status["memory"]["available"])
        self.assertEqual(14.92, status["pressure"]["memory"]["some"]["avg300"])
        self.assertEqual({}, status["pressure"]["cpu"])
        self.assertEqual({"cpu-thermal": 50.147}, status["temperatures_celsius"])


if __name__ == "__main__":
    unittest.main()
