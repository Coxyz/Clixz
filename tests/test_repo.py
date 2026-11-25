"""`clixz repo`: listing checkouts without running git, and planning a new one."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from clixz.repo import (
    foreign_entry,
    komodo_hook,
    list_repos,
    plan_add,
    plan_fix,
    public_url,
    validate_repo_url,
)


class ListTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _repo(self, name: str, head: str, config: str = "") -> None:
        git = self.base / name / ".git"
        git.mkdir(parents=True)
        (git / "HEAD").write_text(head, encoding="utf-8")
        (git / "config").write_text(config, encoding="utf-8")

    def test_branch_and_remote_are_read_from_the_git_directory(self) -> None:
        self._repo("clixz", "ref: refs/heads/main\n",
                   '[remote "origin"]\n\turl = git@github.com:Coxyz/Clixz.git\n')
        [row] = list_repos(self.base)
        self.assertEqual("clixz", row["name"])
        self.assertEqual("main", row["branch"])
        self.assertEqual("git@github.com:Coxyz/Clixz.git", row["remote"])

    def test_a_detached_head_shows_the_commit(self) -> None:
        self._repo("x", "0123456789abcdef0123456789abcdef01234567\n")
        self.assertEqual("0123456789ab", list_repos(self.base)[0]["branch"])

    def test_a_plain_directory_is_listed_as_not_a_repository(self) -> None:
        (self.base / "notes").mkdir()
        self.assertEqual([{"name": "notes", "path": str(self.base / "notes"), "git": False}],
                         list_repos(self.base))

    def test_a_token_in_an_https_remote_is_never_listed(self) -> None:
        self._repo("x", "ref: refs/heads/main\n",
                   '[remote "origin"]\n\turl = https://ghp_secret@github.com/me/x.git\n')
        self.assertEqual("https://github.com/me/x.git", list_repos(self.base)[0]["remote"])

    def test_a_missing_base_directory_is_an_empty_list(self) -> None:
        self.assertEqual([], list_repos(self.base / "nope"))


class UrlTests(unittest.TestCase):
    def test_credentials_are_stripped_from_https_only(self) -> None:
        self.assertEqual("https://h/p", public_url("https://user:pw@h/p"))
        self.assertEqual("ssh://git@h/p", public_url("ssh://git@h/p"))
        self.assertEqual("git@h:p", public_url("git@h:p"))

    def test_the_three_forms_are_accepted(self) -> None:
        for url in ("https://github.com/me/x.git", "ssh://git@github.com/me/x.git",
                    "git@github.com:me/x.git"):
            validate_repo_url(url)

    def test_a_url_cannot_be_an_option_or_a_local_path(self) -> None:
        for url in ("--upload-pack=touch /tmp/x", "-oProxyCommand=x", "/etc", "file:///etc",
                    "https://h/p; rm -rf /"):
            with self.assertRaises(ValueError, msg=url):
                validate_repo_url(url)


class PlanTests(unittest.TestCase):
    def test_without_a_url_it_is_an_empty_repository(self) -> None:
        commands = plan_add(Path("/opt/repos"), "demo")
        self.assertEqual(["mkdir", "-p", "/opt/repos/demo"], commands[0])
        self.assertEqual("init", commands[1][1])

    def test_with_a_url_it_is_a_clone_and_the_url_follows_a_double_dash(self) -> None:
        [command] = plan_add(Path("/opt/repos"), "demo", "https://github.com/me/x.git")
        self.assertEqual(["git", "clone", "--", "https://github.com/me/x.git",
                          "/opt/repos/demo"], command)

    def test_an_existing_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "demo").mkdir()
            with self.assertRaises(ValueError):
                plan_add(Path(tmp), "demo")

    def test_a_name_cannot_leave_the_base_directory(self) -> None:
        for name in ("../x", "a/b", ".hidden", ""):
            with self.assertRaises(ValueError, msg=name):
                plan_add(Path("/opt/repos"), name)


if __name__ == "__main__":
    unittest.main()

    def test_with_an_owner_the_new_checkout_is_handed_over(self) -> None:
        commands = plan_add(Path("/opt/repos"), "demo", None, "dev:dev", "g+rwX")
        self.assertEqual(["chown", "-R", "-h", "dev:dev", "/opt/repos/demo"], commands[-2])
        self.assertEqual(["chmod", "-R", "g+rwX", "/opt/repos/demo"], commands[-1])


class OwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        (self.base / "demo" / "src").mkdir(parents=True)
        (self.base / "demo" / "src" / "a.py").write_text("", encoding="utf-8")
        self.me = (os.getuid(), os.getgid())

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_checkout_owned_by_us_has_no_foreign_entry(self) -> None:
        self.assertIsNone(foreign_entry(self.base / "demo", *self.me))

    def test_the_first_foreign_entry_is_reported(self) -> None:
        # Another uid stands in for root: we cannot chown in a test.
        self.assertEqual(self.base / "demo", foreign_entry(self.base / "demo", self.me[0] + 1,
                                                           self.me[1]))

    def test_fix_never_follows_a_symlinked_checkout(self) -> None:
        (self.base / "link").symlink_to(self.base / "demo")
        with self.assertRaisesRegex(ValueError, "symlink"):
            plan_fix(self.base, "link", "dev:dev", None)

    def test_fix_is_a_recursive_chown_that_does_not_dereference(self) -> None:
        self.assertEqual([["chown", "-R", "-h", "dev:dev", str(self.base / "demo")]],
                         plan_fix(self.base, "demo", "dev:dev", None))

    def test_the_komodo_hook_uses_numeric_ids_and_chmods_first(self) -> None:
        self.assertEqual("chown -R -h 997:1006 .", komodo_hook(997, 1006, None))
        self.assertEqual("chmod -R g+rwX . && chown -R -h 997:1006 .",
                         komodo_hook(997, 1006, "g+rwX"))
