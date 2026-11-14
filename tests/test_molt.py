from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from moltwarden.molt import MoltError, load_ledger
from moltwarden.redteam import _signed_bundle


OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "requires OpenSSL Ed25519 support")
class SignedLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(self.private)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        subprocess.run([OPENSSL, "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        der = subprocess.run([OPENSSL, "pkey", "-pubin", "-in", str(self.public), "-outform", "DER"], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout
        self.bundle = _signed_bundle(self.root / "bundle", "I", "warden.identity.genesis", {"identity_id": "agent", "genesis_hash": "a" * 64}, self.private, self.public, der[-32:].hex())

    def tearDown(self):
        self.temporary.cleanup()

    def test_valid_event_hash_and_ed25519_signature_verify(self):
        events = load_ledger(self.bundle)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].type, "warden.identity.genesis")
        self.assertEqual(events[0].seq, 0)

    def test_tampered_signature_is_rejected(self):
        ledger_path = self.bundle.root / "stores" / "ledger" / "events.jsonl"
        event = json.loads(ledger_path.read_text(encoding="ascii"))
        original = event["sig"]
        event["sig"] = ("0" if original[0] != "0" else "1") + original[1:]
        ledger_path.write_text(json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
        with self.assertRaises(MoltError):
            load_ledger(self.bundle)

    def test_tampered_event_payload_is_rejected_by_hash_chain(self):
        ledger_path = self.bundle.root / "stores" / "ledger" / "events.jsonl"
        event = json.loads(ledger_path.read_text(encoding="ascii"))
        event["payload"]["identity_id"] = "forged"
        ledger_path.write_text(json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
        with self.assertRaises(MoltError):
            load_ledger(self.bundle)


if __name__ == "__main__":
    unittest.main()
