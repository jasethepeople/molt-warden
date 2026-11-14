from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from moltwarden.bundle import Bundle
from moltwarden.keychain import KeychainError, verify_keychain
from moltwarden.molt import _public_key_bytes, canonical_json


OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "requires OpenSSL Ed25519 support")
class KeychainTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "bundle"
        keys = self.root / "keys"
        keys.mkdir(parents=True)
        self.root_private, self.root_public = self._keypair("root")
        self.next_private, self.next_public = self._keypair("next")
        self.root_hash = hashlib.sha256(_public_key_bytes(self.root_public)).hexdigest()
        self.next_hash = hashlib.sha256(_public_key_bytes(self.next_public)).hexdigest()
        shutil.copyfile(self.root_public, keys / "root.pem")
        shutil.copyfile(self.next_public, keys / "next.pem")
        unsigned = {
            "issuer": "genesis",
            "subject": "rotated",
            "public_key": "next.pem",
            "issuer_key_sha256": self.root_hash,
            "subject_key_sha256": self.next_hash,
        }
        signature = self._sign(self.root_private, canonical_json(unsigned).encode("ascii"))
        self.document = {
            "format": "molt-warden-keychain/v1",
            "root": {"id": "genesis", "public_key": "root.pem", "sha256": self.root_hash},
            "delegations": [{**unsigned, "signature": signature.hex()}],
            "current": "rotated",
        }
        self._write_document()
        self.bundle = Bundle(self.root, {"bundle_id": "test", "trial": "IV", "fixture": "twin-v0"})

    def tearDown(self):
        self.temporary.cleanup()

    def _run(self, *args):
        return subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def _keypair(self, name: str):
        private = self.root / f"{name}-private.pem"
        public = self.root / f"{name}-public.pem"
        self._run(OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(private))
        self._run(OPENSSL, "pkey", "-in", str(private), "-pubout", "-out", str(public))
        return private, public

    def _sign(self, private: Path, message: bytes) -> bytes:
        path = self.root / "signed-message.bin"
        path.write_bytes(message)
        return self._run(OPENSSL, "pkeyutl", "-sign", "-inkey", str(private), "-rawin", "-in", str(path)).stdout

    def _write_document(self):
        path = self.root / "keys" / "delegation.json"
        path.write_text(json.dumps(self.document, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    def test_valid_root_to_current_chain_verifies(self):
        verified = verify_keychain(self.bundle)
        self.assertEqual(verified.ids, ("genesis", "rotated"))
        self.assertEqual(verified.current_id, "rotated")
        self.assertEqual(dict(verified.public_keys)["rotated"], _public_key_bytes(self.next_public).hex())

    def test_modified_delegation_signature_is_rejected(self):
        original = self.document["delegations"][0]["signature"]
        self.document["delegations"][0]["signature"] = ("0" if original[0] != "0" else "1") + original[1:]
        self._write_document()
        with self.assertRaises(KeychainError):
            verify_keychain(self.bundle)

    def test_current_key_must_be_chain_tip(self):
        self.document["current"] = "genesis"
        self._write_document()
        with self.assertRaisesRegex(KeychainError, "tip"):
            verify_keychain(self.bundle)


if __name__ == "__main__":
    unittest.main()
