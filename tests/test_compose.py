"""The compose template and the lint that replaced spec.json."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from clixz.compose import lint_compose, lint_service, summarize, template
from clixz.config import parse_config


def _config() -> object:
    return parse_config({
        "root_dir": "/srv/docker",
        "categories": {"apps": {"user": "root", "group": "root"}},
    })


def _levels(findings, level: str) -> list[str]:
    return [f.message for f in findings if f.level == level]


class TemplateTests(unittest.TestCase):
    def test_template_is_valid_yaml_with_one_service(self) -> None:
        doc = yaml.safe_load(template(_config(), "apps", "demo"))
        self.assertEqual(["demo"], list(doc["services"]))

    def test_template_carries_the_house_hardening(self) -> None:
        body = yaml.safe_load(template(_config(), "apps", "demo"))["services"]["demo"]
        self.assertEqual(["ALL"], body["cap_drop"])
        self.assertIn("no-new-privileges:true", body["security_opt"])
        self.assertEqual(["/.env"[1:]], body["env_file"])
        self.assertEqual("unless-stopped", body["restart"])

    def test_uid_gid_is_quoted(self) -> None:
        # An unquoted 988:982 is a YAML 1.1 sexagesimal int (59339), which would
        # silently run the container under the wrong uid.
        body = yaml.safe_load(template(_config(), "apps", "demo"))["services"]["demo"]
        self.assertIsInstance(body.get("user"), str)

    def test_volume_paths_are_absolute(self) -> None:
        # Komodo deploys the stack; its working directory is not guaranteed to
        # be the service directory, so "./config" is not safe here.
        body = yaml.safe_load(template(_config(), "apps", "demo"))["services"]["demo"]
        for entry in body["volumes"]:
            self.assertTrue(entry.startswith("/srv/docker/apps/demo/"), entry)

    def test_template_says_it_may_be_edited(self) -> None:
        self.assertIn("edit freely", template(_config(), "apps", "demo"))


class LintTests(unittest.TestCase):
    def test_privileged_is_an_error(self) -> None:
        found = lint_service("x", {"image": "a:1", "privileged": True})
        self.assertTrue(any("privileged" in m for m in _levels(found, "error")))

    def test_host_networking_is_an_error(self) -> None:
        found = lint_service("x", {"image": "a:1", "network_mode": "host"})
        self.assertTrue(any("network_mode" in m for m in _levels(found, "error")))

    def test_docker_socket_is_an_error(self) -> None:
        found = lint_service("x", {"image": "a:1",
                                   "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]})
        self.assertTrue(any("docker.sock" in m for m in _levels(found, "error")))

    def test_config_dir_read_only_is_not_an_error(self) -> None:
        # The MCP container legitimately reads /etc/clixz/config.yaml.
        found = lint_service("x", {"image": "a:1",
                                   "volumes": ["/etc/clixz/config.yaml:/etc/clixz/config.yaml:ro"]})
        self.assertEqual([], _levels(found, "error"))

    def test_config_dir_read_write_is_an_error(self) -> None:
        found = lint_service("x", {"image": "a:1", "volumes": ["/etc/clixz:/etc/clixz"]})
        self.assertTrue(any("rewrite the rules" in m for m in _levels(found, "error")))

    def test_docker_socket_read_only_is_still_an_error(self) -> None:
        # :ro on a socket does not stop you talking to the daemon behind it.
        found = lint_service("x", {"image": "a:1",
                                   "volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"]})
        self.assertTrue(any("docker.sock" in m for m in _levels(found, "error")))

    def test_mounting_root_is_an_error(self) -> None:
        found = lint_service("x", {"image": "a:1", "volumes": ["/:/rootfs:ro"]})
        self.assertTrue(any("mounts /" in m for m in _levels(found, "error")))

    def test_port_on_every_interface_is_a_warning(self) -> None:
        found = lint_service("x", {"image": "a:1", "ports": ["9120:9120"]})
        self.assertTrue(any("every interface" in m for m in _levels(found, "warn")))

    def test_port_bound_to_localhost_is_not_flagged(self) -> None:
        found = lint_service("x", {"image": "a:1", "ports": ["127.0.0.1:9120:9120"]})
        self.assertEqual([], [m for m in _levels(found, "warn") if "interface" in m])

    def test_latest_tag_is_a_warning(self) -> None:
        found = lint_service("x", {"image": "prom/prometheus:latest"})
        self.assertTrue(any(":latest" in m for m in _levels(found, "warn")))

    def test_pinned_tag_is_not_flagged(self) -> None:
        found = lint_service("x", {"image": "eclipse-mosquitto:2"})
        self.assertEqual([], [m for m in _levels(found, "warn") if "latest" in m])

    def test_digest_pin_is_not_flagged(self) -> None:
        found = lint_service("x", {"image": "nginx@sha256:" + "a" * 64})
        self.assertEqual([], [m for m in _levels(found, "warn") if "tag" in m])

    def test_host_path_outside_the_service_tree_is_a_warning(self) -> None:
        found = lint_service("x", {"image": "a:1", "volumes": ["/etc/localtime:/etc/localtime:ro"]},
                             Path("/srv/docker/apps/x"))
        self.assertTrue(any("/etc/localtime" in m for m in _levels(found, "warn")))

    def test_path_inside_the_service_tree_is_not_flagged(self) -> None:
        found = lint_service("x", {"image": "a:1", "volumes": ["/srv/docker/apps/x/data:/data"]},
                             Path("/srv/docker/apps/x"))
        self.assertEqual([], [m for m in _levels(found, "warn") if "host path" in m])

    def test_a_clean_service_raises_no_error_or_warning(self) -> None:
        body = yaml.safe_load(template(_config(), "apps", "demo"))["services"]["demo"]
        body["image"] = "nginx:1.27-alpine"
        found = lint_service("demo", body, Path("/srv/docker/apps/demo"))
        self.assertEqual([], _levels(found, "error"))
        self.assertEqual([], _levels(found, "warn"))

    def test_lint_never_raises_on_a_broken_body(self) -> None:
        self.assertTrue(lint_service("x", "not-a-mapping"))  # type: ignore[arg-type]


class FileTests(unittest.TestCase):
    def test_empty_compose_is_a_warning_not_a_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "compose.yaml"
            path.write_text("", encoding="utf-8")
            self.assertEqual("warn", lint_compose(path)[0].level)

    def test_unparsable_compose_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "compose.yaml"
            path.write_text("services: [oops\n", encoding="utf-8")
            self.assertEqual("error", lint_compose(path)[0].level)

    def test_summarize_reads_image_ports_and_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "compose.yaml"
            path.write_text(
                "services:\n  a:\n    image: nginx:1\n    container_name: web\n"
                "    ports: ['80:80']\n", encoding="utf-8")
            image, ports, names = summarize(path)
            self.assertEqual(("nginx:1", ["80:80"], ["web"]), (image, ports, names))
