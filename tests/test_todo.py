"""The shared to-do list."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

import yaml

from clixz.todo import OPEN_STATES, STATES, TodoError, TodoStore


class TodoTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "todo.yaml"
        self.store = TodoStore(self.path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_states_are_the_four_the_operator_asked_for(self) -> None:
        self.assertEqual(("todo", "doing", "done", "archived"), STATES)
        self.assertEqual(("todo", "doing"), OPEN_STATES)

    def test_a_missing_file_is_an_empty_list(self) -> None:
        self.assertEqual([], self.store.items())
        self.assertFalse(self.path.exists())

    def test_an_empty_file_is_an_empty_list(self) -> None:
        self.path.write_text("", encoding="utf-8")
        self.assertEqual([], self.store.items())

    def test_add_creates_the_file_with_a_todo_item(self) -> None:
        item = self.store.add("Sauvegardes", "restic + timer")
        self.assertEqual(1, item.id)
        self.assertEqual("todo", item.state)
        self.assertEqual(item.created, item.updated)
        self.assertEqual(["Sauvegardes"], [i.title for i in TodoStore(self.path).items()])

    def test_ids_keep_increasing_after_a_delete(self) -> None:
        self.store.add("one")
        two = self.store.add("two")
        self.store.remove(two.id)
        self.assertEqual(3, self.store.add("three").id)

    def test_update_changes_only_what_is_given_and_bumps_updated(self) -> None:
        item = self.store.add("title", "first description")
        time.sleep(1.1)
        changed = self.store.update(item.id, state="doing")
        self.assertEqual("doing", changed.state)
        self.assertEqual("title", changed.title)
        self.assertEqual("first description", changed.description)
        self.assertEqual(item.created, changed.created)
        self.assertNotEqual(item.updated, changed.updated)

    def test_an_unknown_state_is_refused(self) -> None:
        item = self.store.add("x")
        with self.assertRaises(TodoError):
            self.store.update(item.id, state="blocked")
        with self.assertRaises(TodoError):
            self.store.add("y", state="later")

    def test_a_title_must_be_one_non_empty_line(self) -> None:
        for title in ("", "   ", "two\nlines", "x" * 201):
            with self.assertRaises(TodoError, msg=repr(title)):
                self.store.add(title)

    def test_a_non_string_is_refused_rather_than_coerced(self) -> None:
        with self.assertRaises(TodoError):
            self.store.add(3)  # type: ignore[arg-type]
        with self.assertRaises(TodoError):
            self.store.add("ok", description=["list"])  # type: ignore[arg-type]

    def test_an_unknown_id_is_a_todo_error(self) -> None:
        with self.assertRaises(TodoError):
            self.store.get(42)
        with self.assertRaises(TodoError):
            self.store.update(42, title="x")
        with self.assertRaises(TodoError):
            self.store.remove(42)

    def test_remove_returns_what_it_removed(self) -> None:
        item = self.store.add("gone")
        self.assertEqual(item.id, self.store.remove(item.id).id)
        self.assertEqual([], self.store.items())

    def test_a_multiline_description_survives_a_round_trip_as_a_block(self) -> None:
        text = "line one\nline two\n\n- a bullet"
        item = self.store.add("multi", text)
        self.assertEqual(text, TodoStore(self.path).get(item.id).description)
        self.assertIn("description: |", self.path.read_text(encoding="utf-8"))

    def test_a_corrupt_file_is_reported_and_left_untouched(self) -> None:
        self.path.write_text("items: [unclosed", encoding="utf-8")
        with self.assertRaises(TodoError):
            self.store.add("x")
        with self.assertRaises(TodoError):
            self.store.items()
        self.assertEqual("items: [unclosed", self.path.read_text(encoding="utf-8"))

    def test_a_file_of_the_wrong_shape_is_reported(self) -> None:
        self.path.write_text(yaml.safe_dump({"items": "not a list"}), encoding="utf-8")
        with self.assertRaises(TodoError):
            self.store.items()

    def test_writing_in_place_keeps_the_inode(self) -> None:
        self.store.add("first")
        inode = self.path.stat().st_ino
        self.store.add("second")
        self.assertEqual(inode, self.path.stat().st_ino)

    def test_a_new_file_is_readable_by_everyone(self) -> None:
        self.store.add("first")
        self.assertEqual(0o664, self.path.stat().st_mode & 0o777)

    def test_to_dict_is_what_the_json_output_carries(self) -> None:
        item = self.store.add("t", "d")
        self.assertEqual({"id", "title", "state", "created", "updated", "description"},
                         set(item.to_dict()))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
