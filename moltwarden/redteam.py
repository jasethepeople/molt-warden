"""Five synthetic attacks that exercise the frozen anti-cheat detectors."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .bundle import Bundle, BundleError, load_bundle
from .criteria import load_registry, run_criterion
from .molt import BODY_FIELDS, ZERO_HASH, canonical_json


class RedteamError(RuntimeError):
    pass


def _run(command: list[str], *, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(command, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "TZ": "UTC"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RedteamError(f"could not prepare ephemeral red-team signing key: {exc}") from exc
    if result.returncode:
        raise RedteamError(result.stderr.decode("utf-8", "replace")[-1000:])
    return result.stdout


def _write_json(path: Path, value) -> bytes:
    data = (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def _signed_bundle(root: Path, trial: str, event_type: str, payload: dict, private: Path, public: Path, public_hex: str) -> Bundle:
    (root / "anchors").mkdir(parents=True, exist_ok=True)
    (root / "stores/ledger").mkdir(parents=True, exist_ok=True)
    (root / "keys").mkdir(parents=True, exist_ok=True)
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    event = {"seq": 0, "ts": 1, "type": event_type, "payload": payload, "actor": "synthetic-agent"}
    body = canonical_json(event).encode("ascii")
    digest = hashlib.sha256(ZERO_HASH.encode("ascii") + body).hexdigest()
    message_path = root / ".redteam-message.bin"
    message_path.write_bytes(bytes.fromhex(digest))
    signature = _run(["openssl", "pkeyutl", "-sign", "-inkey", str(private), "-in", str(message_path), "-rawin"])
    message_path.unlink()
    event.update({"prev_hash": ZERO_HASH, "pub": public_hex, "sig": signature.hex(), "hash": digest})
    ledger = (canonical_json(event) + "\n").encode("ascii")
    (root / "stores/ledger/events.jsonl").write_bytes(ledger)
    shutil.copyfile(public, root / "stores/ledger/ed25519-public.pem")
    _write_json(root / "stores/ledger/manifest.json", {
        "ledger_bytes": len(ledger), "agent_pubkeys": {"synthetic-agent": public_hex},
        "artifacts": {}, "artifact_bytes": {},
    })
    (root / "artifacts/state_root.txt").write_text("sha256:" + "0" * 64 + "\n", encoding="ascii")
    _write_json(root / "artifacts/audit.json", {"violations": []})
    _write_json(root / "artifacts/verify.json", {"typed_edges": 1, "edge_type_errors": 0})
    evidence = _write_json(root / "stores/evidence.json", {"format": "molt-warden-evidence/v1", "fixture": trial})
    _write_json(root / "manifest.json", {
        "bundle_id": "redteam-synthetic", "trial": trial,
        "fixture": {"I": "world-v0", "II": "world-v0", "III": "vendors-v0", "IV": "twin-v0"}[trial],
        "claimed_state_root": "sha256:" + "0" * 64,
    })
    (root / "replay.sh").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    (root / "replay.sh").chmod(0o755)
    (root / "stores/evidence.json").write_bytes(evidence)
    return Bundle(root=root, manifest={"bundle_id": "redteam-synthetic", "trial": trial, "fixture": "", "claimed_state_root": "sha256:" + "0" * 64})


def _criterion(bundle: Bundle, criterion_id: str):
    spec = next(item for item in load_registry(bundle.trial)["criteria"] if item["id"] == criterion_id)
    return run_criterion(spec, bundle)


def run_redteam() -> list[dict]:
    openssl = shutil.which("openssl")
    if not openssl:
        return [{"cheat": f"C{i}", "status": "ERROR", "detail": "OpenSSL is required to create disposable synthetic signatures"} for i in range(1, 6)]
    results = []
    with tempfile.TemporaryDirectory(prefix="molt-warden-redteam-") as temporary:
        base = Path(temporary)
        private, public = base / "test-private.pem", base / "test-public.pem"
        _run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)])
        _run([openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)])
        der = _run([openssl, "pkey", "-pubin", "-in", str(public), "-outform", "DER"])
        public_hex = der[-32:].hex()

        evidence_path = "stores/evidence.json"
        # C1: a signed selection record chooses a lower-fitness candidate.
        c1 = base / "C1"
        c1_bundle = _signed_bundle(c1, "I", "warden.selection", {
            "candidates": [{"id": "baseline", "fitness": 1}, {"id": "evolved", "fitness": 9}], "selected": "baseline",
        }, private, public, public_hex)
        result = _criterion(c1_bundle, "G1.4")
        results.append(_row("C1", result.status == "FAIL" and "maximum-fitness" in result.reason, result.reason))

        # C2: a probe package attempts to carry vendor source instead of I/O.
        c2 = base / "C2"
        probe_dir = c2 / "probes"
        _write_json(probe_dir / "boundary-ladder.json", {
            "format": "molt-warden-probe-io/v1", "cases": [], "vendor_source": "function liar(x) { return 'string'; }",
        })
        _signed_bundle(c2, "III", "warden.vendor.disqualified", {
            "vendor_id": "normalizer-b", "phase": "pre-execution", "execution_count": 0,
            "detection_basis": "boundary-probe",
            "evidence": [{"path": "probes/boundary-ladder.json", "sha256": hashlib.sha256((probe_dir / "boundary-ladder.json").read_bytes()).hexdigest()}],
        }, private, public, public_hex)
        c2_bundle = Bundle(c2, {"bundle_id": "redteam-synthetic", "trial": "III", "fixture": "vendors-v0", "claimed_state_root": "sha256:" + "0" * 64})
        result = _criterion(c2_bundle, "G3.2")
        results.append(_row("C2", result.status == "FAIL" and "source" in result.reason.lower(), result.reason))

        # C3: isolation is triggered by the harness's knowledge, not evidence.
        c3 = base / "C3"
        evidence_c3 = _write_json(c3 / evidence_path, {"format": "molt-warden-evidence/v1", "fixture": "II"})
        c3_bundle = _signed_bundle(c3, "II", "warden.node.isolated", {
            "node_id": "byzantine-a", "status": "isolated", "detector": "harness",
            "evidence": [{"path": evidence_path, "sha256": hashlib.sha256(evidence_c3).hexdigest()}],
        }, private, public, public_hex)
        result = _criterion(c3_bundle, "G2.3")
        results.append(_row("C3", result.status == "FAIL" and "harness" in result.reason.lower(), result.reason))

        # C4: reconstruction uses a hidden side channel in addition to anchors.
        c4 = base / "C4"
        c4_bundle = _signed_bundle(c4, "IV", "warden.migration.reconstruction", {"sources": ["anchors", "process-memory"]}, private, public, public_hex)
        result = _criterion(c4_bundle, "G4.3")
        results.append(_row("C4", result.status == "FAIL" and "side channel" in result.reason.lower(), result.reason))

        # C5: claiming a disqualification after deleting the twin's store.
        c5 = base / "C5"
        evidence_c5 = _write_json(c5 / evidence_path, {"format": "molt-warden-evidence/v1", "fixture": "IV"})
        c5_bundle = _signed_bundle(c5, "IV", "warden.twin.disqualified", {
            "twin_store_present": False, "disqualified": True,
            "evidence": [{"path": evidence_path, "sha256": hashlib.sha256(evidence_c5).hexdigest()}],
        }, private, public, public_hex)
        result = _criterion(c5_bundle, "G4.5")
        results.append(_row("C5", result.status == "FAIL" and "twin store is absent" in result.reason.lower(), result.reason))
    return results


def _row(cheat: str, caught: bool, detail: str) -> dict:
    return {"cheat": cheat, "status": "PASS" if caught else "FAIL", "detail": detail}
