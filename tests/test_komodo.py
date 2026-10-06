"""Creating a new service's stack in Komodo."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from clixz.config import parse_config
from clixz.komodo import (
    Client,
    Credentials,
    KomodoError,
    client_for,
    create_stack,
    load_credentials,
)


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeKomodo:
    """Answers like Komodo Core: POST /read/<Request> and /write/<Request>."""

    def __init__(self, stacks=(), servers=({"id": "s1", "name": "boxyz"},), fail=None):
        self.stacks = [dict(s) for s in stacks]
        self.servers = ([dict(s) if isinstance(s, dict) else s for s in servers]
                        if isinstance(servers, (list, tuple)) else servers)
        self.fail = fail
        self.requests: list[tuple[str, dict, dict]] = []

    def __call__(self, request, timeout=None):
        if isinstance(self.fail, Exception):
            raise self.fail
        body = json.loads(request.data.decode("utf-8"))
        headers = {k.lower(): v for k, v in request.header_items()}
        self.requests.append((request.full_url, body, headers))
        name = request.full_url.rsplit("/", 1)[-1]
        if name == "ListStacks":
            answer = self.stacks
        elif name == "ListServers":
            answer = self.servers
        elif name == "CreateStack":
            self.stacks.append({"id": "new", "name": body["name"]})
            answer = {"id": "new", "name": body["name"], "config": body["config"]}
        else:  # pragma: no cover - a request the client should never make
            raise AssertionError(name)
        return _Response(json.dumps(answer).encode("utf-8"))

    def created(self) -> dict | None:
        for url, body, _ in self.requests:
            if url.endswith("/write/CreateStack"):
                return body
        return None


def _config(server: str | None = None) -> object:
    komodo = {"credentials": "/nonexistent.yaml"}
    if server:
        komodo["server"] = server
    return parse_config({"root_dir": "/srv/docker",
                         "categories": {"apps": {"user": "root", "group": "root"}},
                         "komodo": komodo})


def _client(fake: FakeKomodo) -> Client:
    return Client("http://core:9120", Credentials(key="K", secret="S"), opener=fake)


class CreateStackTests(unittest.TestCase):
    def test_the_stack_is_created_files_on_host_in_the_service_directory(self) -> None:
        fake = FakeKomodo()
        message = create_stack(_config(), name="demo", run_directory="/services/apps/demo",
                               client=_client(fake))
        self.assertEqual({"name": "demo", "config": {
            "server_id": "s1", "files_on_host": True, "run_directory": "/services/apps/demo",
        }}, fake.created())
        self.assertIn("demo", message)

    def test_the_api_key_travels_in_komodo_headers(self) -> None:
        fake = FakeKomodo()
        create_stack(_config(), name="demo", run_directory="/x", client=_client(fake))
        _, _, headers = fake.requests[0]
        self.assertEqual(("K", "S"), (headers["x-api-key"], headers["x-api-secret"]))
        self.assertEqual("application/json", headers["content-type"])

    def test_an_existing_stack_is_left_alone(self) -> None:
        fake = FakeKomodo(stacks=[{"id": "a", "name": "demo"}])
        message = create_stack(_config(), name="demo", run_directory="/x", client=_client(fake))
        self.assertIsNone(fake.created())
        self.assertIn("already", message)

    def test_a_named_server_is_resolved_by_name_or_id(self) -> None:
        servers = [{"id": "s1", "name": "boxyz"}, {"id": "s2", "name": "other"}]
        for wanted in ("other", "s2"):
            fake = FakeKomodo(servers=servers)
            create_stack(_config(wanted), name="demo", run_directory="/x", client=_client(fake))
            self.assertEqual("s2", fake.created()["config"]["server_id"], wanted)

    def test_several_servers_and_none_named_is_an_error(self) -> None:
        fake = FakeKomodo(servers=[{"id": "s1", "name": "a"}, {"id": "s2", "name": "b"}])
        with self.assertRaises(KomodoError):
            create_stack(_config(), name="demo", run_directory="/x", client=_client(fake))
        self.assertIsNone(fake.created())

    def test_an_unknown_server_is_an_error(self) -> None:
        with self.assertRaises(KomodoError):
            create_stack(_config("nope"), name="demo", run_directory="/x",
                         client=_client(FakeKomodo()))

    def test_an_answer_of_an_unexpected_shape_is_a_komodo_error(self) -> None:
        for servers in ([{"name": "no-id"}], [["not", "a", "mapping"]], "nonsense"):
            with self.assertRaises(KomodoError, msg=servers):
                create_stack(_config(), name="demo", run_directory="/x",
                             client=_client(FakeKomodo(servers=servers)))

    def test_an_http_error_carries_komodos_message(self) -> None:
        error = urllib.error.HTTPError(
            "http://core:9120/read/ListStacks", 401, "Unauthorized", {},
            io.BytesIO(b'{"error":"Invalid client credentials","trace":[]}'))
        with self.assertRaises(KomodoError) as caught:
            create_stack(_config(), name="demo", run_directory="/x",
                         client=_client(FakeKomodo(fail=error)))
        self.assertIn("Invalid client credentials", str(caught.exception))

    def test_an_unreachable_core_is_a_komodo_error(self) -> None:
        with self.assertRaises(KomodoError):
            create_stack(_config(), name="demo", run_directory="/x",
                         client=_client(FakeKomodo(fail=urllib.error.URLError("refused"))))


class CredentialsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "komodo.yaml"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, text: str, mode: int = 0o600) -> None:
        self.path.write_text(text, encoding="utf-8")
        self.path.chmod(mode)

    def test_key_secret_and_optional_url(self) -> None:
        self._write("key: K\nsecret: S\nurl: http://127.0.0.1:9120/\n")
        self.assertEqual(Credentials("K", "S", "http://127.0.0.1:9120"), load_credentials(self.path))

    def test_a_missing_file_says_how_to_make_one(self) -> None:
        with self.assertRaises(KomodoError) as caught:
            load_credentials(self.path)
        self.assertIn("API key", str(caught.exception))

    def test_a_file_others_can_read_is_refused(self) -> None:
        self._write("key: K\nsecret: S\n", mode=0o644)
        with self.assertRaises(KomodoError):
            load_credentials(self.path)

    def test_a_missing_secret_is_refused(self) -> None:
        self._write("key: K\n")
        with self.assertRaises(KomodoError):
            load_credentials(self.path)

    def test_without_a_url_the_container_address_is_used(self) -> None:
        self._write("key: K\nsecret: S\n")
        config = parse_config({"root_dir": "/srv/docker",
                               "categories": {"apps": {"user": "root", "group": "root"}},
                               "komodo": {"credentials": str(self.path)}})
        with mock.patch("clixz.komodo.container_ip", return_value="172.19.0.8"):
            self.assertEqual("http://172.19.0.8:9120", client_for(config).url)
        with mock.patch("clixz.komodo.container_ip", return_value=None):
            with self.assertRaises(KomodoError):
                client_for(config)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
