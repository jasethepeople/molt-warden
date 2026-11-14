"""Cross-trial invariants, with host-observed replay telemetry for X3/X6."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from .bundle import Bundle, BundleError, read_json
from .criteria import _ledger, _valid_evidence, _hash, Undecidable
from .keychain import KeychainError, verify_keychain
from .molt import MoltError, _public_key_bytes, _verify_signature, canonical_json
from .verdict import Result


def _anchor_records(bundle: Bundle, events):
    path = bundle.path("anchors/finality.jsonl")
    raw = path.read_bytes()
    if not raw.endswith(b"\n"):
        raise Undecidable("anchors/finality.jsonl: final newline is missing")
    previous = "0" * 64
    records = []
    for line_no, line in enumerate(raw.splitlines(), 1):
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise Undecidable(f"anchors/finality.jsonl: invalid record at line {line_no}: {exc}") from exc
        if not isinstance(row, dict) or set(row) != {"anchor_seq", "event_seq", "event_hash", "prev_hash", "hash"}:
            raise Undecidable(f"anchors/finality.jsonl: malformed record at line {line_no}")
        if type(row["anchor_seq"]) is not int or row["anchor_seq"] != line_no - 1 or type(row["event_seq"]) is not int or row["event_seq"] < 0:
            raise Undecidable(f"anchors/finality.jsonl: invalid sequence at line {line_no}")
        if row["prev_hash"] != previous or not _hash(row["event_hash"]) or not _hash(row["hash"]):
            raise Undecidable(f"anchors/finality.jsonl: broken hash chain at line {line_no}")
        body = {key: value for key, value in row.items() if key != "hash"}
        digest = hashlib.sha256(canonical_json(body).encode("ascii")).hexdigest()
        if digest != row["hash"] or row["event_seq"] >= len(events) or events[row["event_seq"]].hash != row["event_hash"]:
            raise Undecidable(f"anchors/finality.jsonl: anchor does not bind to a recomputed ledger event at line {line_no}")
        records.append(row)
        previous = digest
    if not records:
        raise Undecidable("anchors/finality.jsonl: no anchor records")
    return records


def _fail(spec: dict, reason: str) -> Result:
    return Result(spec.get("id", "?"), "FAIL", reason)


def _pass(spec: dict, reason: str) -> Result:
    return Result(spec.get("id", "?"), "PASS", reason)


def _x1(bundle: Bundle) -> Result:
    events = _ledger(bundle)
    records = _anchor_records(bundle, events)
    finalities = [event for event in events if event.type == "warden.finality" and isinstance(event.payload, dict)]
    if not finalities:
        return _fail({"id": "X1"}, "anchors/finality.jsonl: no signed finality claims to anchor")
    for event in finalities:
        target = event.payload.get("event_seq")
        head = event.payload.get("head_hash")
        if type(target) is not int or target < 0 or target >= event.seq or not _hash(head) or events[target].hash != head:
            return _fail({"id": "X1"}, f"stores/ledger/events.jsonl: finality event {event.seq} cites an invalid target")
        if not any(record["event_seq"] == target and record["event_hash"] == head for record in records):
            return _fail({"id": "X1"}, f"anchors/finality.jsonl: finality event {event.seq} has no matching anchor")
    return _pass({"id": "X1"}, "anchors/finality.jsonl")


def _x2(bundle: Bundle) -> Result:
    outcome = bundle.cache.get("replay_outcome")
    if outcome is None or not outcome.ok or len(outcome.runs) != 2:
        return _fail({"id": "X2"}, "artifacts/state_root.txt: two successful replay records are required")
    roots = [run.get("state_root") for run in outcome.runs]
    if any(not isinstance(root, str) for root in roots) or roots[0] != roots[1] or roots[0] != bundle.state_root():
        return _fail({"id": "X2"}, "artifacts/state_root.txt: host-observed replay roots disagree")
    return _pass({"id": "X2"}, "artifacts/state_root.txt")


def _x3(bundle: Bundle) -> Result:
    outcome = bundle.cache.get("replay_outcome")
    runs = outcome.runs if outcome else []
    if len(runs) != 2:
        return _fail({"id": "X3"}, "replay.sh: grader-owned process-tree telemetry is missing")
    attack_runs = outcome.attack_runs if outcome else []
    required_attacks = 2 if bundle.trial in {"II", "IV"} else 0
    if len(attack_runs) != required_attacks:
        return _fail({"id": "X3"}, "attacks/: grader-owned process-tree telemetry for both attack reruns is missing")
    for run in [*attack_runs, *runs]:
        audit = run.get("runtime")
        if not isinstance(audit, dict) or audit.get("host_sample_source") != "docker-stats-and-inspect" or audit.get("process_samples", 0) < 1 or not audit.get("runner_seen"):
            return _fail({"id": "X3"}, "replay.sh: grader did not observe the sealed runner process")
        if audit.get("unattributed_process") is not False or not audit.get("trial_process_seen"):
            return _fail({"id": "X3"}, "replay.sh: grader process-tree diff found an unattributed process or no trial process")
        if not isinstance(audit.get("process_tree"), list) or not audit["process_tree"]:
            return _fail({"id": "X3"}, "replay.sh: grader process-tree sample is empty")
    return _pass({"id": "X3"}, "replay.sh: grader-owned Docker process-tree samples")


def _x4(bundle: Bundle) -> Result:
    events = _ledger(bundle)
    kinds = {"warden.vendor.disqualified", "warden.node.isolated", "warden.twin.disqualified"}
    for event in events:
        if event.type in kinds:
            if not isinstance(event.payload, dict) or not _valid_evidence(bundle, event.payload.get("evidence"), prefixes=("stores/", "probes/", "anchors/")):
                return _fail({"id": "X4"}, f"stores/ledger/events.jsonl#seq={event.seq}: disqualification lacks local hash-verified replay evidence")
    return _pass({"id": "X4"}, "stores/ledger/events.jsonl")


def _x5(bundle: Bundle) -> Result:
    try:
        chain = verify_keychain(bundle)
        chronicle = bundle.path("artifacts/chronicle.txt").read_bytes()
        signature = bundle.path("artifacts/chronicle.sig").read_bytes()
        if len(signature) == 128:
            try:
                signature = bytes.fromhex(signature.decode("ascii"))
            except (UnicodeError, ValueError):
                pass
        _verify_signature(chain.current_pem, signature, chronicle)
        events = _ledger(bundle)
        current_raw = _public_key_bytes(chain.current_pem)
        if not events or events[-1].pub != current_raw.hex():
            return _fail({"id": "X5"}, "keys/delegation.json: chronicle signer is not the current ledger signer")
        return _pass({"id": "X5"}, "artifacts/chronicle.txt")
    except (BundleError, KeychainError, MoltError, OSError, ValueError, TypeError) as exc:
        return _fail({"id": "X5"}, f"artifacts/chronicle.sig: invalid or unrooted chronicle signature ({exc})")


def _x6(bundle: Bundle) -> Result:
    outcome = bundle.cache.get("replay_outcome")
    runs = outcome.runs if outcome else []
    if len(runs) != 2:
        return _fail({"id": "X6"}, "replay.sh: grader-owned resource samples are missing")
    attack_runs = outcome.attack_runs if outcome else []
    required_attacks = 2 if bundle.trial in {"II", "IV"} else 0
    if len(attack_runs) != required_attacks:
        return _fail({"id": "X6"}, "attacks/: grader-owned resource samples for both attack reruns are missing")
    if not outcome or outcome.duration_s > 900:
        return _fail({"id": "X6"}, "replay.sh: total grader-observed wall-clock budget exceeded")
    for run in [*attack_runs, *runs]:
        audit = run.get("runtime")
        if not isinstance(audit, dict) or audit.get("host_sample_source") != "docker-stats-and-inspect":
            return _fail({"id": "X6"}, "replay.sh: grader-owned resource log is missing")
        samples = audit.get("resource_samples")
        if not isinstance(samples, list) or not samples:
            return _fail({"id": "X6"}, "replay.sh: Docker daemon returned no resource samples")
        if audit.get("oom_killed") is not False or audit.get("memory_limit_bytes") != 512 * 1024 * 1024 or audit.get("nano_cpus") != 2_000_000_000 or audit.get("pids_limit") != 256:
            return _fail({"id": "X6"}, "replay.sh: grader-observed container limits are absent or incorrect")
        if any(not isinstance(sample, dict) or type(sample.get("memory_bytes")) is not int or type(sample.get("pids")) is not int or isinstance(sample.get("cpu_percent"), bool) or not isinstance(sample.get("cpu_percent"), (int, float)) or not math.isfinite(sample["cpu_percent"]) for sample in samples):
            return _fail({"id": "X6"}, "replay.sh: grader resource sample is malformed")
        max_memory = max(sample["memory_bytes"] for sample in samples)
        max_cpu = max(sample["cpu_percent"] for sample in samples)
        max_pids = max(sample["pids"] for sample in samples)
        if max_memory < 0 or max_memory > audit["memory_limit_bytes"] or max_cpu < 0 or max_cpu > 205 or max_pids < 1 or max_pids > audit["pids_limit"]:
            return _fail({"id": "X6"}, "replay.sh: observed memory/CPU/process usage exceeds the grader-enforced budget or is malformed")
        if type(run.get("duration_s")) not in (int, float) or run["duration_s"] > 900:
            return _fail({"id": "X6"}, "replay.sh: grader-observed wall-clock budget exceeded")
    return _pass({"id": "X6"}, "replay.sh: grader-owned Docker/cgroup resource samples")


_HANDLERS = {
    "x1_anchor_completeness": _x1,
    "x2_replay_determinism": _x2,
    "x3_no_privileged_harness": _x3,
    "x4_evidence_locality": _x4,
    "x5_signed_narration": _x5,
    "x6_budget_honesty": _x6,
}


def run_invariant(spec: dict, bundle: Bundle) -> Result:
    handler = _HANDLERS.get(spec.get("check"))
    if handler is None:
        return _fail(spec, "artifacts/verify.json: unknown invariant check")
    try:
        result = handler(bundle)
        result.id = spec.get("id", result.id)
        return result
    except (BundleError, Undecidable, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        evidence = spec.get("id")
        path = "replay.sh" if evidence in {"X3", "X6"} else "anchors/finality.jsonl" if evidence == "X1" else "stores/ledger/events.jsonl"
        return _fail(spec, f"{path}: invariant could not be established ({exc})")
