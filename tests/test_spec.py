"""Tests for the typed service spec and compose generation.

The security argument of this module is *inexpressibility*: the dangerous
compose constructs have no field in the structure, so they cannot reach the
rendered output. Each attack scenario below asserts that.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from clixz.config import CategoryConfig, Config, PrincipalConfig, RuleConfig, SettingsConfig
from clixz.spec import (
    DEFAULT_NETWORKS,
    Mount,
    ServiceSpec,
    SpecError,
    apply_patch,
    render_compose,
    spec_from_dict,
    spec_to_dict,
    validate,
)


def _config() -> Config:
    return Config(
        root_dir=Path("/srv/docker"),
        settings=SettingsConfig(principals={"komodo": PrincipalConfig(name="root", kind="group")}),
        categories={"apps": CategoryConfig(user="root", group="root")},
        rules={"service_dir": RuleConfig(mode="750")},
        exclude=[],
    )


def _minimal(**over) -> dict:
    base = {"category": "apps", "service": "demo", "image": "nginx:1.27.3"}
    base.update(over)
    return base


def _render(**over) -> dict:
    cfg = _config()
    return yaml.safe_load(render_compose(validate(spec_from_dict(_minimal(**over)), cfg), cfg))


class ClosedStructureTests(unittest.TestCase):
    """Every dangerous compose key is rejected as an unknown field."""

    def test_rejects_dangerous_keys(self) -> None:
        for key, value in [
            ("privileged", True),
            ("network_mode", "host"),
            ("pid", "host"),
            ("ipc", "host"),
            ("userns_mode", "host"),
            ("devices", ["/dev/mem:/dev/mem"]),
            ("cap_add", ["SYS_ADMIN"]),
            ("volumes", ["/var/run/docker.sock:/var/run/docker.sock"]),
            ("env_file", ["../bitwarden/.env"]),
            ("environment", {"SECRET": "x"}),
            ("ports", ["0.0.0.0:80:80"]),
            ("build", "."),
            ("entrypoint", "/bin/sh"),
            ("sysctls", {"net.ipv4.ip_forward": "1"}),
            ("security_opt", ["seccomp:unconfined"]),
            ("x-evil", "anything"),
        ]:
            with self.subTest(key=key):
                with self.assertRaises(SpecError) as cm:
                    spec_from_dict(_minimal(**{key: value}))
                self.assertIn("Unknown field", str(cm.exception))


class ImageTests(unittest.TestCase):
    def test_requires_a_pinned_tag(self) -> None:
        with self.assertRaises(SpecError):
            validate(spec_from_dict(_minimal(image="nginx")), _config())

    def test_rejects_latest(self) -> None:
        with self.assertRaises(SpecError):
            validate(spec_from_dict(_minimal(image="nginx:latest")), _config())

    def test_rejects_interpolation(self) -> None:
        # A ${...} would make the validated text differ from the deployed one.
        with self.assertRaises(SpecError):
            validate(spec_from_dict(_minimal(image="${EVIL}:1.0")), _config())

    def test_accepts_a_digest(self) -> None:
        digest = "nginx@sha256:" + "a" * 64
        self.assertEqual(
            validate(spec_from_dict(_minimal(image=digest)), _config()).image, digest
        )


class MountTests(unittest.TestCase):
    def test_only_config_and_data_are_mountable(self) -> None:
        for source in ("/var/run", "/", "..", "/etc", "secrets"):
            with self.subTest(source=source):
                with self.assertRaises(SpecError):
                    validate(
                        spec_from_dict(_minimal(mounts=[{"source": source, "target": "/x"}])),
                        _config(),
                    )

    def test_rejects_traversal_in_target(self) -> None:
        for target in ("../../etc", "relative/path", "/x/../../etc"):
            with self.subTest(target=target):
                with self.assertRaises(SpecError):
                    validate(
                        spec_from_dict(_minimal(mounts=[{"source": "data", "target": target}])),
                        _config(),
                    )

    def test_config_is_always_read_only(self) -> None:
        # Even when the caller explicitly asks for read-write.
        doc = _render(mounts=[{"source": "config", "target": "/config", "read_only": False}])
        self.assertEqual(
            doc["services"]["demo"]["volumes"], ["/srv/docker/apps/demo/config:/config:ro"]
        )

    def test_mount_paths_are_derived_not_supplied(self) -> None:
        doc = _render(mounts=[{"source": "data", "target": "/data"}])
        self.assertEqual(
            doc["services"]["demo"]["volumes"], ["/srv/docker/apps/demo/data:/data"]
        )


class NamingTests(unittest.TestCase):
    def test_rejects_unknown_category(self) -> None:
        with self.assertRaises(SpecError):
            validate(spec_from_dict(_minimal(category="../etc")), _config())

    def test_rejects_traversal_in_service_name(self) -> None:
        with self.assertRaises(SpecError):
            validate(spec_from_dict(_minimal(service="../nginx")), _config())

    def test_rejects_unknown_network(self) -> None:
        for net in ("host", "bridge", "none"):
            with self.subTest(net=net):
                with self.assertRaises(SpecError):
                    validate(spec_from_dict(_minimal(network=net)), _config())


class LimitTests(unittest.TestCase):
    def test_caps_memory(self) -> None:
        with self.assertRaises(SpecError):
            validate(spec_from_dict(_minimal(mem_limit="64g")), _config())

    def test_rejects_bad_port(self) -> None:
        for port in ("0", "70000", "abc"):
            with self.subTest(port=port):
                with self.assertRaises(SpecError):
                    validate(spec_from_dict(_minimal(expose=[port])), _config())


class RenderTests(unittest.TestCase):
    def test_hardening_is_always_present(self) -> None:
        svc = _render()["services"]["demo"]
        self.assertEqual(svc["security_opt"], ["no-new-privileges:true"])
        self.assertEqual(svc["cap_drop"], ["ALL"])
        self.assertEqual(svc["restart"], "unless-stopped")
        self.assertIn("pids_limit", svc)
        self.assertIn("mem_limit", svc)

    def test_env_file_is_always_the_service_own(self) -> None:
        self.assertEqual(_render()["services"]["demo"]["env_file"], [".env"])

    def test_never_emits_host_ports(self) -> None:
        self.assertNotIn("ports", _render(expose=["8080"])["services"]["demo"])

    def test_network_is_external(self) -> None:
        doc = _render()
        self.assertEqual(doc["networks"][DEFAULT_NETWORKS[0]], {"external": True})

    def test_uid_gid_survives_as_a_string(self) -> None:
        # Unquoted, "988:59" parses as the YAML 1.1 sexagesimal integer 59339,
        # which would silently run the container under the wrong uid.
        self.assertEqual(yaml.safe_load("user: 988:59")["user"], 59339)
        cfg = Config(
            root_dir=Path("/srv/docker"),
            settings=SettingsConfig(principals={}),
            categories={"apps": CategoryConfig(user="root", group="root")},
            rules={}, exclude=[],
        )
        spec = validate(spec_from_dict(_minimal()), cfg)
        user = yaml.safe_load(render_compose(spec, cfg))["services"]["demo"].get("user")
        if user is not None:
            self.assertIsInstance(user, str)

    def test_output_reparses(self) -> None:
        cfg = _config()
        text = render_compose(validate(spec_from_dict(_minimal()), cfg), cfg)
        self.assertIsInstance(yaml.safe_load(text), dict)
        self.assertIn("Generated by clixz", text)


class PatchTests(unittest.TestCase):
    """`update --patch` merges partial fields and re-validates the whole spec."""

    def _spec(self) -> ServiceSpec:
        return validate(spec_from_dict(_minimal(expose=["8080"], mem_limit="256m")), _config())

    def test_replaces_only_the_given_fields(self) -> None:
        merged = validate(apply_patch(self._spec(), {"mem_limit": "1g"}), _config())
        self.assertEqual(merged.mem_limit, "1g")
        self.assertEqual(merged.image, "nginx:1.27.3")
        self.assertEqual(merged.expose, ["8080"])

    def test_lists_are_replaced_not_merged(self) -> None:
        merged = validate(apply_patch(self._spec(), {"expose": ["9090"]}), _config())
        self.assertEqual(merged.expose, ["9090"])

    def test_identity_fields_are_not_patchable(self) -> None:
        for key, value in (("category", "infra"), ("service", "other")):
            with self.subTest(key=key):
                with self.assertRaises(SpecError):
                    apply_patch(self._spec(), {key: value})

    def test_rejects_unknown_and_empty_patches(self) -> None:
        with self.assertRaises(SpecError):
            apply_patch(self._spec(), {"privileged": True})
        with self.assertRaises(SpecError):
            apply_patch(self._spec(), {})

    def test_merged_spec_is_revalidated(self) -> None:
        # A patch cannot leave the service in a state `create` would have refused.
        with self.assertRaises(SpecError):
            validate(apply_patch(self._spec(), {"image": "nginx:latest"}), _config())

    def test_round_trips_through_json(self) -> None:
        spec = self._spec()
        self.assertEqual(
            spec_to_dict(validate(spec_from_dict(spec_to_dict(spec)), _config())),
            spec_to_dict(spec),
        )


if __name__ == "__main__":
    unittest.main()
