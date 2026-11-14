"""Frozen criterion registry and fail-closed, evidence-backed checks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from .bundle import Bundle, BundleError, read_json
from .molt import MoltError, MoltEvent, load_ledger
from .verdict import Result

REGISTRY = Path(__file__).with_name("criteria.json")


class Undecidable(Exception):
    pass


def load_registry(trial: str) -> dict:
    try:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != "0.1.0":
            raise ValueError("unexpected registry version")
        criteria, invariants = data["criteria"], data["invariants"]
        if not isinstance(criteria, list) or len(criteria) != 27 or not isinstance(invariants, list) or len(invariants) != 6:
            raise ValueError("registry must contain exactly 27 criteria and 6 invariants")
        if len({item["id"] for item in criteria}) != 27 or len({item["id"] for item in invariants}) != 6:
            raise ValueError("registry IDs must be unique")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"criterion registry is invalid: {exc}") from exc
    if trial not in {"I", "II", "III", "IV"}:
        raise ValueError(f"unknown trial {trial!r}")
    return {
        "criteria": [item for item in criteria if item["trial"] == trial],
        "invariants": invariants,
        "version": data["version"],
    }


def _ledger(bundle: Bundle) -> list[MoltEvent]:
    cached = bundle.cache.get("molt_events")
    if cached is not None:
        return cached
    try:
        events = load_ledger(bundle)
    except (MoltError, BundleError) as exc:
        raise Undecidable(f"stores/ledger/events.jsonl: invalid or missing MOLT-CORE evidence ({exc})") from exc
    if not events:
        raise Undecidable("stores/ledger/events.jsonl: empty MOLT-CORE ledger")
    bundle.cache["molt_events"] = events
    return events


def _payloads(events: list[MoltEvent], kind: str) -> list[tuple[MoltEvent, dict]]:
    return [(event, event.payload) for event in events if event.type == kind and isinstance(event.payload, dict)]


def _one(events: list[MoltEvent], kind: str) -> tuple[MoltEvent, dict]:
    found = _payloads(events, kind)
    if not found:
        raise Undecidable(f"stores/ledger/events.jsonl: missing signed {kind} record")
    return found[-1]


def _bool(value) -> bool:
    return value is True


def _integer(value) -> bool:
    return type(value) is int


def _hash(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _valid_evidence(bundle: Bundle, evidence, *, prefixes: tuple[str, ...] = ()) -> bool:
    if not isinstance(evidence, list) or not evidence:
        return False
    for item in evidence:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not _hash(item.get("sha256")):
            return False
        rel = item["path"]
        if rel == "transcript.md" or rel.startswith("transcript.md/"):
            return False
        if prefixes and not any(rel.startswith(prefix) for prefix in prefixes):
            return False
        try:
            data = bundle.path(rel).read_bytes()
        except (BundleError, OSError):
            return False
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            return False
    return True


def _check_genesis_rooted(bundle, events):
    anchor = _one(events, "warden.identity.genesis")[1]
    genesis_hash = events[0].hash
    path = bundle.path("anchors/genesis.json")
    record = read_json(path)
    if not isinstance(record, dict) or not isinstance(anchor.get("identity_id"), str) or not anchor["identity_id"] or record.get("identity_id") != anchor.get("identity_id") or record.get("genesis_hash") != genesis_hash or anchor.get("genesis_hash") != genesis_hash:
        raise Undecidable("anchors/genesis.json: identity does not bind to the recomputed ledger genesis")
    return "anchors/genesis.json"


def _check_generations(bundle, events):
    rows = _payloads(events, "warden.generation")
    hashes = {row.get("ruleset_hash") for _, row in rows if _hash(row.get("ruleset_hash"))}
    if len(rows) < 10 or len(hashes) < 10:
        raise Undecidable("stores/ledger/events.jsonl: fewer than 10 signed generations with distinct ruleset hashes")
    return "stores/ledger/events.jsonl"


def _check_hotswap_real(bundle, events):
    swaps = _payloads(events, "warden.hotswap")
    genesis = events[0].hash
    if not swaps or any(row.get("genesis_hash") != genesis or row.get("source") != "signed-ledger-event" or not _integer(row.get("post_genesis_manual_edits")) or row.get("post_genesis_manual_edits") != 0 or not _hash(row.get("before_hash")) or not _hash(row.get("after_hash")) or row.get("before_hash") == row.get("after_hash") for _, row in swaps):
        raise Undecidable("stores/ledger/events.jsonl: no verifiable post-genesis hot-swap record or manual edits were declared")
    return "stores/ledger/events.jsonl"


def _check_fitness_monotone(bundle, events):
    selections = _payloads(events, "warden.selection")
    if not selections:
        raise Undecidable("artifacts/verify.json: no signed fitness-selection records")
    for event, row in selections:
        candidates = row.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: missing candidate fitness records")
        valid = [c for c in candidates if isinstance(c, dict) and isinstance(c.get("id"), str) and isinstance(c.get("fitness"), (int, float)) and not isinstance(c.get("fitness"), bool)]
        if len(valid) != len(candidates):
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: malformed candidate fitness")
        best = max(valid, key=lambda item: (item["fitness"], item["id"]))
        if row.get("selected") != best["id"]:
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: selected candidate is not the maximum-fitness candidate")
    return "artifacts/verify.json"


def _check_audit_zero(bundle, events):
    path = bundle.path("artifacts/audit.json")
    data = read_json(path)
    _, signed = _one(events, "warden.audit.completed")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not isinstance(data, dict) or data.get("violations") != [] or not _integer(signed.get("violation_count")) or signed.get("violation_count") != 0 or signed.get("audit_sha256") != digest:
        raise Undecidable("artifacts/audit.json: audit violations are present or the signed audit digest/count does not match")
    return "artifacts/audit.json"


def _check_replay_root(bundle, events):
    replay = bundle.cache.get("replay_outcome")
    if replay is None or not replay.ok or replay.state_root != bundle.state_root():
        raise Undecidable("artifacts/state_root.txt: replay did not reproduce the declared root")
    return "artifacts/state_root.txt"


def _check_threshold(bundle, events):
    row = _one(events, "warden.consensus.configuration")[1]
    nodes = row.get("nodes")
    if not isinstance(nodes, list) or any(not isinstance(node, str) or not node for node in nodes) or len(set(nodes)) < 3 or row.get("threshold") != {"required": 2, "total": 3}:
        raise Undecidable("anchors/consensus.json: signed configuration is not a 2-of-3 threshold over at least three nodes")
    return "anchors/consensus.json"


def _check_isolation(bundle, events):
    row = _one(events, "warden.node.isolated")[1]
    if not isinstance(row.get("node_id"), str) or row.get("status") != "isolated":
        raise Undecidable("stores/ledger/events.jsonl: malicious node was not isolated")
    return "stores/ledger/events.jsonl"


def _check_evidence_based(bundle, events):
    event, row = _one(events, "warden.node.isolated")
    evidence = row.get("evidence")
    if row.get("detector") == "harness" or row.get("method") == "harness-identification" or not _valid_evidence(bundle, evidence, prefixes=("stores/", "anchors/")):
        raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: isolation relies on harness identity or lacks hash-verified local evidence")
    return "stores/ledger/events.jsonl"


def _check_no_loss(bundle, events):
    event, row = _one(events, "warden.reconciliation")
    before, after = row.get("valid_before"), row.get("valid_after")
    if not isinstance(before, list) or not isinstance(after, list) or set(before) != set(after) or row.get("lost_event_ids") != []:
        raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: valid event set changed during recovery")
    return "stores/ledger/events.jsonl"


def _check_self_heal(bundle, events):
    _, row = _one(events, "warden.self_heal")
    if not _bool(row.get("healed")) or not _integer(row.get("restart_count")) or row.get("restart_count") != 0 or not _bool(row.get("converged")):
        raise Undecidable("stores/ledger/events.jsonl: recovery required a restart or did not converge")
    return "stores/ledger/events.jsonl"


def _check_partition_safety(bundle, events):
    partitions = _payloads(events, "warden.partition")
    finality = _payloads(events, "warden.finality")
    if not partitions or not finality or any(not _integer(row.get("safety_violations")) or row.get("safety_violations") != 0 for _, row in partitions):
        raise Undecidable("anchors/partition.json: partition test or zero-violation finality evidence is missing")
    by_epoch = {}
    for _, row in finality:
        epoch, head = row.get("epoch"), row.get("head_hash")
        if not _integer(epoch) or not _hash(head) or (epoch in by_epoch and by_epoch[epoch] != head):
            raise Undecidable("anchors/partition.json: conflicting or malformed finality heads")
        by_epoch[epoch] = head
    return "anchors/partition.json"


def _check_liar_precontract(bundle, events):
    event, row = _one(events, "warden.vendor.disqualified")
    expected = bundle.cache.get("runtime_liar_id")
    if not expected or row.get("vendor_id") != expected or row.get("phase") != "pre-execution" or not _integer(row.get("execution_count")) or row.get("execution_count") != 0:
        raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: harness-selected liar was not disqualified before execution")
    return "stores/ledger/events.jsonl"


def _probe_io_only(bundle: Bundle) -> bool:
    try:
        path = bundle.path("probes/boundary-ladder.json")
        data = read_json(path)
    except (BundleError, OSError):
        return False
    if not isinstance(data, dict) or set(data) != {"format", "cases"} or data.get("format") != "molt-warden-probe-io/v1" or not isinstance(data.get("cases"), list) or not data["cases"]:
        return False
    for case in data["cases"]:
        if not isinstance(case, dict) or set(case) != {"case_id", "input", "output"} or not isinstance(case.get("case_id"), str):
            return False
    return True


def _check_disqual_evidence(bundle, events):
    event, row = _one(events, "warden.vendor.disqualified")
    evidence = row.get("evidence")
    if row.get("detection_basis") in {"vendor-source", "source-code", "harness-identity"} or not _probe_io_only(bundle) or not _valid_evidence(bundle, evidence, prefixes=("probes/", "stores/")):
        raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: disqualification is not grounded in hash-verified black-box I/O; probe source is forbidden")
    return "stores/ledger/events.jsonl"


def _check_edge_typing(bundle, events):
    path = bundle.path("artifacts/verify.json")
    data = read_json(path)
    _, signed = _one(events, "warden.edges.checked")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not isinstance(data, dict) or not _integer(data.get("typed_edges")) or data["typed_edges"] < 1 or not _integer(data.get("edge_type_errors")) or data["edge_type_errors"] != 0 or signed.get("verify_sha256") != digest or signed.get("typed_edges") != data["typed_edges"] or signed.get("edge_type_errors") != 0:
        raise Undecidable("artifacts/verify.json: type-check counts are absent, inconsistent with signed event, or contain errors")
    return "artifacts/verify.json"


def _check_proof_gate(bundle, events):
    path = bundle.path("attacks/poisoned-variant.json")
    data = read_json(path)
    event, row = _one(events, "warden.proof_gate")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not isinstance(data, dict) or data.get("poisoned") is not True or data.get("expected") != "abort" or row.get("input_sha256") != digest or row.get("outcome") != "abort":
        raise Undecidable(f"attacks/poisoned-variant.json: proof gate did not abort the exact poisoned input (event {event.seq})")
    return "attacks/poisoned-variant.json"


def _check_drift_handled(bundle, events):
    event, row = _one(events, "warden.vendor.drift")
    first_violation = row.get("first_violation_tick")
    handled = row.get("handled_tick")
    if not _integer(first_violation) or not _integer(handled) or handled >= first_violation or row.get("action") not in {"abort", "rollback", "swap"}:
        raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: vendor drift was not handled before a violation")
    return "stores/ledger/events.jsonl"


def _check_swap_integrity(bundle, events):
    swaps = _payloads(events, "warden.vendor.swap")
    if not swaps or any(not _hash(row.get("pre_state_hash")) or row.get("pre_state_hash") != row.get("post_state_hash") or row.get("event_chain_preserved") is not True for _, row in swaps):
        raise Undecidable("stores/ledger/events.jsonl: hot-swap did not preserve the pre/post state and event chain")
    return "stores/ledger/events.jsonl"


def _check_rollback(bundle, events):
    event, row = _one(events, "warden.vendor.rollback")
    if row.get("rollback") is not True or row.get("pipeline_continued") is not True or not _hash(row.get("restored_state_hash")):
        raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: failed swap was not rolled back before pipeline continuation")
    return "stores/ledger/events.jsonl"


def _check_delegation_complete(bundle, events):
    from .keychain import KeychainError, verify_keychain
    try:
        chain = verify_keychain(bundle)
    except KeychainError as exc:
        raise Undecidable(f"keys/delegation.json: cryptographic delegation verification failed ({exc})") from exc
    public_keys = dict(chain.public_keys)
    if not events or events[-1].pub != public_keys.get(chain.current_id):
        raise Undecidable("keys/delegation.json: current genesis-descended key did not sign the latest ledger event")
    for event in events:
        if public_keys.get(event.actor) != event.pub:
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: signer is not linked to the genesis key")
    return "keys/delegation.json"


def _check_two_phase(bundle, events):
    migrations = _payloads(events, "warden.migration")
    if len(migrations) < 3:
        raise Undecidable("stores/ledger/events.jsonl: fewer than three migration records")
    for event, row in migrations:
        tombstone, resume = row.get("tombstone_seq"), row.get("resumption_seq")
        if not _integer(tombstone) or not _integer(resume) or tombstone < 0 or resume >= event.seq or tombstone >= resume:
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: migration lacks an earlier ordered tombstone and resumption")
        if not any(item.seq == tombstone and item.type == "warden.migration.tombstone" for item in events) or not any(item.seq == resume and item.type == "warden.migration.resumption" for item in events):
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: referenced tombstone/resumption event is absent")
    return "stores/ledger/events.jsonl"


def _check_anchor_only(bundle, events):
    migrations = _payloads(events, "warden.migration.reconstruction")
    if not migrations:
        raise Undecidable("replay: migration reconstruction record is missing")
    for event, row in migrations:
        sources = row.get("sources")
        if not isinstance(sources, list) or not sources or any(source != "anchors" for source in sources):
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: reconstruction used non-anchor state or a side channel")
    return "replay"


def _check_no_rollback(bundle, events):
    finals = [(event, row) for event, row in _payloads(events, "warden.finality")]
    if not finals:
        raise Undecidable("anchors/finality.json: finality history is missing")
    prior_epoch, prior_seq = -1, -1
    seen = {}
    for event, row in finals:
        epoch, seq, head = row.get("epoch"), row.get("seq"), row.get("head_hash")
        if not _integer(epoch) or not _integer(seq) or epoch < 0 or seq < 0 or seq >= event.seq or seq >= len(events) or not _hash(head) or events[seq].hash != head or epoch < prior_epoch or seq < prior_seq:
            raise Undecidable(f"anchors/finality.json#seq={event.seq}: finality rolled back, cites an invalid head, or is malformed")
        if epoch in seen and seen[epoch] != head:
            raise Undecidable(f"anchors/finality.json#seq={event.seq}: equivocation at one epoch")
        seen[epoch] = head
        prior_epoch, prior_seq = epoch, seq
    return "anchors/finality.json"


def _check_twin_disqualified(bundle, events):
    event, row = _one(events, "warden.twin.disqualified")
    try:
        twin_store = bundle.path("stores/twin")
        store_present = twin_store.is_dir() and any(child.is_file() for child in twin_store.rglob("*"))
    except BundleError:
        store_present = False
    if not store_present or row.get("twin_store_present") is not True or row.get("disqualified") is not True or not _valid_evidence(bundle, row.get("evidence"), prefixes=("stores/twin/", "anchors/")):
        raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: twin store is absent, twin was not disqualified, or replayable evidence is missing")
    return "stores/ledger/events.jsonl"


def _check_horizon(bundle, events):
    obligations = _payloads(events, "warden.horizon.obligation")
    if not obligations:
        raise Undecidable("stores/ledger/events.jsonl: lineage horizon obligation missing")
    for event, row in obligations:
        honored = row.get("honored_seq")
        if row.get("honored") is not True or not _integer(honored) or honored <= event.seq or not any(item.seq == honored for item in events):
            raise Undecidable(f"stores/ledger/events.jsonl#seq={event.seq}: horizon obligation was not honored by a later lineage event")
    return "stores/ledger/events.jsonl"


def _check_policy_migration(bundle, events):
    policies = {row.get("epoch"): row for _, row in _payloads(events, "warden.policy.epoch")}
    epoch2, epoch3 = policies.get(2), policies.get(3)
    if not epoch2 or not epoch3 or not _hash(epoch2.get("policy_hash")) or epoch3.get("policy_hash") != epoch2.get("policy_hash") or epoch3.get("enforced") is not True:
        raise Undecidable("stores/ledger/events.jsonl: epoch-2 policy was not verified as enforced in epoch 3")
    return "stores/ledger/events.jsonl"


_HANDLERS: dict[str, Callable] = {
    "check_genesis_rooted": _check_genesis_rooted,
    "check_generations": _check_generations,
    "check_hotswap_real": _check_hotswap_real,
    "check_fitness_monotone": _check_fitness_monotone,
    "check_audit_zero": _check_audit_zero,
    "check_replay_root": _check_replay_root,
    "check_threshold": _check_threshold,
    "check_isolation": _check_isolation,
    "check_evidence_based": _check_evidence_based,
    "check_no_loss": _check_no_loss,
    "check_self_heal": _check_self_heal,
    "check_partition_safety": _check_partition_safety,
    "check_liar_precontract": _check_liar_precontract,
    "check_disqual_evidence": _check_disqual_evidence,
    "check_edge_typing": _check_edge_typing,
    "check_proof_gate": _check_proof_gate,
    "check_drift_handled": _check_drift_handled,
    "check_swap_integrity": _check_swap_integrity,
    "check_rollback": _check_rollback,
    "check_delegation_complete": _check_delegation_complete,
    "check_two_phase": _check_two_phase,
    "check_anchor_only": _check_anchor_only,
    "check_no_rollback": _check_no_rollback,
    "check_twin_disqualified": _check_twin_disqualified,
    "check_horizon": _check_horizon,
    "check_policy_migration": _check_policy_migration,
}


def run_criterion(spec: dict, bundle: Bundle) -> Result:
    check = spec.get("check")
    handler = _HANDLERS.get(check)
    if handler is None:
        return Result(spec.get("id", "?"), "FAIL", f"stores/ledger/events.jsonl: undecidable: unknown criterion check {check!r}")
    if spec.get("trial") != bundle.trial:
        return Result(spec.get("id", "?"), "FAIL", f"manifest.json: criterion trial does not match bundle trial")
    try:
        events = _ledger(bundle)
        evidence_path = handler(bundle, events)
        return Result(spec["id"], "PASS", evidence_path)
    except (Undecidable, BundleError, OSError, ValueError, TypeError, KeyError) as exc:
        evidence_path = spec.get("evidence", "stores/ledger/events.jsonl")
        return Result(spec.get("id", "?"), "FAIL", f"{evidence_path}: undecidable: {exc}")
