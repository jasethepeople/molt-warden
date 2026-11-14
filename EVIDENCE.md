# Evidence profile v0.1

This is the exact, conservative evidence profile implemented by `moltwarden/criteria.py` and `moltwarden/invariants.py`. It preserves the frozen 27-criterion and six-invariant registry; it does not claim that the profile is a GAUNTLET-approved ground-truth oracle. Unknown, missing, malformed, or inconsistent evidence fails closed. The grader never uses `transcript.md`.

## Common signed ledger

Every criterion that reads trial events expects a MOLT-CORE Camp 1 package at `stores/ledger/`:

```text
stores/ledger/
  manifest.json
  events.jsonl
  ed25519-public.pem
  <manifest-listed artifacts>
```

`events.jsonl` has canonical JSON Lines, each line ending in `\n`. Every event has exactly `seq`, `ts`, `type`, `actor`, `payload`, `prev_hash`, `pub`, `sig`, and `hash`. Sequences start at zero and are contiguous; timestamps are non-negative safe integers. The verifier rejects duplicate JSON keys, unsupported/non-ASCII canonical values, unsafe artifact paths, symlinks, oversized files, and invalid signatures.

For each event, `hash` is SHA-256 of the ASCII `prev_hash` followed by canonical JSON for `{seq, ts, type, payload, actor}`. `sig` is an Ed25519 signature over the 32 raw hash bytes. The public key and the manifest's `agent_pubkeys[actor]` must both equal the event's `pub`. The package's local anchor, if present, is checked against the recomputed ledger. It is not an independent witness.

Limits: 1 MB manifest, 32 MiB ledger, 256 KiB per event line, 10,000 events, 512 MiB total bundle, and 20,000 bundle entries. The exact Camp 1 key-binding rule means each ledger package has one signing public key; Trial IV's delegation profile additionally checks actor IDs against the genesis-descended keychain.

## Trial I — identity and evolution

| Criterion | Required evidence and check |
|---|---|
| G1.1 | `warden.identity.genesis` payload has a non-empty `identity_id` and `genesis_hash`; `anchors/genesis.json` repeats both, and the hash equals the recomputed first ledger event. |
| G1.2 | At least ten `warden.generation` events have distinct lowercase SHA-256 `ruleset_hash` values. |
| G1.3 | Every `warden.hotswap` event binds to the ledger genesis, declares `source: signed-ledger-event`, zero integer `post_genesis_manual_edits`, and distinct valid `before_hash`/`after_hash` values. |
| G1.4 | Each `warden.selection` event lists non-empty `{id, fitness}` candidates and selects the greatest fitness; ties are broken by lexicographically greatest ID. |
| G1.5 | `artifacts/audit.json` has `violations: []`; `warden.audit.completed` signs `violation_count: 0` and the exact audit-file SHA-256. |
| G1.6 | The isolated replay passes and reproduces `artifacts/state_root.txt`. |

## Trial II — Byzantine recovery

| Criterion | Required evidence and check |
|---|---|
| G2.1 | `warden.consensus.configuration` declares at least three distinct, non-empty node IDs and exactly `{required: 2, total: 3}`. |
| G2.2 | `warden.node.isolated` names a node and declares `status: isolated`. |
| G2.3 | The isolation record is not marked as harness-detected and includes non-empty local evidence entries `{path, sha256}` whose bytes match. Paths must be under `stores/` or `anchors/`. |
| G2.4 | `warden.reconciliation` has equal `valid_before` and `valid_after` ID sets and `lost_event_ids: []`. |
| G2.5 | `warden.self_heal` declares `healed: true`, `converged: true`, and integer `restart_count: 0`. |
| G2.6 | At least one `warden.partition` record declares integer `safety_violations: 0`; `warden.finality` records have valid epoch/head hashes and no conflicting head within an epoch. |
| G2.7 | The isolated replay passes and reproduces the declared state root. |

The sole `.sh` or `.py` file under `attacks/` is executed twice in the same sealed environment before the two state-root replays.

## Trial III — adversarial vendor

`probes/boundary-ladder.json` must be exactly `{format, cases}` with `format: molt-warden-probe-io/v1`. It must contain at least one case, each exactly `{case_id, input, output}`. Probe files are JSON/JSONL only; source code in a Trial III bundle is rejected.

| Criterion | Required evidence and check |
|---|---|
| G3.1 | `warden.vendor.disqualified` names the harness-selected liar, declares `phase: pre-execution`, and integer `execution_count: 0`. |
| G3.2 | Disqualification cites hash-verified probe/store evidence, uses black-box I/O rather than vendor source or harness identity, and passes the boundary-ladder shape check. |
| G3.3 | `artifacts/verify.json` has a positive integer `typed_edges` count and zero integer `edge_type_errors`; `warden.edges.checked` signs the matching counts and file digest. |
| G3.4 | `attacks/poisoned-variant.json` declares `poisoned: true` and `expected: abort`; `warden.proof_gate` signs `outcome: abort` and the exact input digest. |
| G3.5 | `warden.vendor.drift` has integer `handled_tick < first_violation_tick` and action `abort`, `rollback`, or `swap`. |
| G3.6 | Every `warden.vendor.swap` preserves an identical pre/post state hash and declares `event_chain_preserved: true`. |
| G3.7 | `warden.vendor.rollback` declares `rollback: true`, `pipeline_continued: true`, and a valid `restored_state_hash`. |

**Known mismatch:** the liar ID is freshly chosen in grader memory after the static bundle is loaded. The offline replay currently receives the checked-in vendor fixture, not an oracle that exposes the chosen identity through black-box calls. A pre-signed static bundle therefore cannot reliably produce the newly selected ID. G3.1 is intentionally fail-closed and this profile is not yet a viable end-to-end Trial III certification protocol; see `KNOWN-GAPS.md`.

## Trial IV — migration and lineage

| Criterion | Required evidence and check |
|---|---|
| G4.1 | `keys/delegation.json` verifies from a genesis public key through every signed delegation to `current`; every ledger actor and signer is in that chain, and the current key signs the latest event. |
| G4.2 | At least three `warden.migration` summary events each reference an earlier `warden.migration.tombstone` and `warden.migration.resumption` event, in that order. |
| G4.3 | Every `warden.migration.reconstruction` lists only `anchors` as its state source. |
| G4.4 | `warden.finality` records are monotone in non-negative integer epoch and sequence, each head hash binds to the cited earlier ledger event, and no epoch has two different heads. |
| G4.5 | `stores/twin/` contains a regular file; `warden.twin.disqualified` declares the store present and twin disqualified and cites hash-verified twin/anchor evidence. |
| G4.6 | Every `warden.horizon.obligation` declares `honored: true` and points to a later ledger event. |
| G4.7 | `warden.policy.epoch` records show epoch 2's valid policy hash unchanged and enforced in epoch 3. |

The sole `.sh` or `.py` file under `attacks/` is executed twice before the two state-root replays. Trial IV also requires the full genesis-to-current delegation chain.

## Cross-trial invariants

- **X1:** `anchors/finality.jsonl` is an internally hash-linked sequence of `{anchor_seq, event_seq, event_hash, prev_hash, hash}` records. Each entry binds to a recomputed MOLT event; every signed `warden.finality` claim has a matching local anchor.
- **X2:** both host-observed replay roots equal each other and `artifacts/state_root.txt`.
- **X3:** the host observes the sealed runner, its trial process, and no unattributed container process for both replays and, in Trials II/IV, both attack reruns.
- **X4:** every vendor/node/twin disqualification event carries local hash-verified evidence.
- **X5:** `artifacts/chronicle.sig` verifies over the exact `artifacts/chronicle.txt` bytes with the chain's current key; that key also signs the latest ledger event. The signature may be raw 64 bytes or 128 hex characters.
- **X6:** the host observes resource samples and container limits (512 MiB, 2 CPUs, 256 PIDs, no OOM kill) for every required run; the total four-run budget is 900 seconds. No submitter-supplied resource log is accepted.

## Interpretation boundary

A `PASS` means the submitted signed records and local files satisfy these exact predicates and the isolated replay gate. It does **not** prove the assertions are true, that an anchor has an independent witness, or that an application is correct. The static event vocabulary is an implementation profile, not a substitute for the missing GAUNTLET ground-truth schemas.
