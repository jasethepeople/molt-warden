from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from moltwarden.bundle import BundleError, load_bundle
from tests.helpers import make_bundle


def point_in_time(tick: int = 10) -> dict:
    return {
        "anchor_tick": tick,
        "anchor_event_id": "we-anchor",
        "session_id": "sentinel-test",
        "triggering_alert_id": "alert-test",
    }


def add_point_in_time(root: Path, value: dict) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["point_in_time"] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def add_events(root: Path, events: list[dict]) -> None:
    path = root / "stores" / "population.jsonl"
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


class PointInTimeBundleTests(unittest.TestCase):
    def test_point_in_time_absent_preserves_v01(self):
        with TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            self.assertEqual(load_bundle(root).trial, "I")

    def test_valid_point_in_time_bundle_loads(self):
        with TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            add_point_in_time(root, point_in_time(10))
            add_events(root, [{"tick": 5, "id": "we-older"}, {"tick": 10, "id": "we-anchor"}])
            self.assertEqual(load_bundle(root).manifest["point_in_time"]["anchor_tick"], 10)

    def test_event_past_anchor_voids(self):
        with TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            add_point_in_time(root, point_in_time(10))
            add_events(root, [{"tick": 10, "id": "we-anchor"}, {"tick": 11, "id": "we-future"}])
            with self.assertRaisesRegex(BundleError, "past point_in_time"):
                load_bundle(root)

    def test_missing_anchor_event_voids(self):
        with TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            add_point_in_time(root, point_in_time())
            add_events(root, [{"tick": 5, "id": "we-other"}])
            with self.assertRaisesRegex(BundleError, "anchor_event_id does not exist"):
                load_bundle(root)

    def test_missing_point_in_time_key_voids(self):
        with TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            pit = point_in_time()
            del pit["session_id"]
            add_point_in_time(root, pit)
            with self.assertRaisesRegex(BundleError, "session_id"):
                load_bundle(root)

    def test_boolean_anchor_tick_is_not_an_integer(self):
        with TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            pit = point_in_time()
            pit["anchor_tick"] = True
            add_point_in_time(root, pit)
            add_events(root, [{"tick": 0, "id": "we-anchor"}])
            with self.assertRaisesRegex(BundleError, "non-negative integer"):
                load_bundle(root)

    def test_duplicate_json_keys_in_event_store_void(self):
        with TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            add_point_in_time(root, point_in_time())
            (root / "stores" / "population.jsonl").write_text(
                '{"tick": 1, "id": "we-anchor", "id": "we-other"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(BundleError, "duplicate key"):
                load_bundle(root)


if __name__ == "__main__":
    unittest.main()
