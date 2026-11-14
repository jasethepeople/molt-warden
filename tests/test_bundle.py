from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from moltwarden.bundle import BundleError, _inventory, load_bundle
from moltwarden.replay import _stage
from tests.helpers import make_bundle


class BundleSafetyTests(unittest.TestCase):
    def test_valid_minimal_bundle_loads(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = make_bundle(Path(temporary) / "bundle")
            bundle = load_bundle(path)
            self.assertEqual(bundle.trial, "I")
            self.assertEqual(bundle.state_root(), "sha256:" + "0" * 64)

    def test_transcript_is_skipped_without_following_or_staging_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle", transcript=True)
            bundle = load_bundle(root)
            dest = Path(temporary) / "staged"
            _stage(bundle.root, dest, ignore_transcript=True)
            self.assertFalse((dest / "transcript.md").exists())
            self.assertEqual(bundle.trial, "I")

    def test_transcript_size_does_not_change_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ignored = root / "nested" / "transcript.md"
            ignored.mkdir(parents=True)
            (ignored / "ignored.bin").touch()
            with (ignored / "ignored.bin").open("r+b") as stream:
                stream.truncate(2 * 1024 * 1024 * 1024)
            self.assertEqual(_inventory(root), (1, 0))

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_bundle(Path(temporary) / "bundle")
            loaded = load_bundle(bundle)
            with self.assertRaises(BundleError):
                loaded.path("../outside")
            with self.assertRaises(BundleError):
                loaded.path("stores\\outside")

    def test_private_key_material_is_void(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            (root / "keys" / "signing.pem").write_text("-----BEGIN PRIVATE KEY-----\\nsecret\\n-----END PRIVATE KEY-----\\n")
            with self.assertRaisesRegex(BundleError, "private key material"):
                load_bundle(root)

    def test_trial_three_rejects_vendor_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle", trial="III")
            (root / "vendor.js").write_text("function liar(x) { return x; }")
            with self.assertRaisesRegex(BundleError, "source code"):
                load_bundle(root)

    def test_trial_specific_attack_script_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle", trial="II")
            (root / "attacks" / "test.sh").unlink()
            with self.assertRaises(BundleError):
                load_bundle(root)

    def test_hardlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            outside = Path(temporary) / "outside.txt"
            outside.write_text("external")
            (root / "stores" / "external.txt").hardlink_to(outside)
            with self.assertRaisesRegex(BundleError, "hardlink"):
                load_bundle(root)


if __name__ == "__main__":
    unittest.main()
