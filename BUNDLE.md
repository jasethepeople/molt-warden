# BUNDLE — submission contract

```text
bundle/
  manifest.json
  anchors/
    genesis.json
    finality.jsonl
    consensus.json                 # Trial II evidence
    partition.json                 # Trial II/IV evidence
  stores/
    ledger/
      manifest.json
      events.jsonl
      ed25519-public.pem
    twin/                          # Trial IV; nonempty
    ...                            # hash-verified supporting evidence
  keys/
    delegation.json
    *.pub.pem                      # public keys only
  probes/
    boundary-ladder.json           # Trial III: I/O only
  attacks/
    <one .sh or .py>               # Trials II and IV; direct child of attacks/
    poisoned-variant.json          # Trial III; no executable attack required
  artifacts/
    state_root.txt
    audit.json
    verify.json
    chronicle.txt
    chronicle.sig
  replay.sh                        # executable; reproduces state_root.txt offline
  transcript.md                    # non-authoritative; excluded from all reads
```

The root directories `anchors/`, `stores/`, `keys/`, and `artifacts/`, plus `manifest.json` and executable `replay.sh`, are required. Trial II and IV require exactly one agent-authored `.sh` or `.py` file directly under `attacks/`; the harness runs it twice before the two replay runs. Trial III requires `probes/boundary-ladder.json` and `attacks/poisoned-variant.json`. Trial IV requires the full cryptographically linked genesis-to-current key chain. The implementation validates paths, rejects symlinks, hardlinks and special files, and caps bundles at 20,000 entries / 512 MiB.

## `manifest.json`

```json
{
  "bundle_id": "<opaque>",
  "trial": "I|II|III|IV",
  "fixture": "world-v0|vendors-v0|twin-v0",
  "claimed_state_root": "sha256:<64 lowercase hex>",
  "claimed_criteria": ["G1.1", "..."],
  "toolchain": { "python": "...", "molt_version": "molt-core/1.0" }
}
```

The fixture is fixed by trial: I/II use `world-v0`, III uses `vendors-v0`, IV uses `twin-v0`. `claimed_criteria` and toolchain labels are informational only. The manifest root must equal the exact `sha256:<64 lowercase hex>` in `artifacts/state_root.txt` and the value reproduced by both runs.

## MOLT ledger and evidence

`stores/ledger/` follows MOLT-CORE Camp 1: canonical nine-field JSONL events, a manifest binding byte lengths and artifact hashes, and an Ed25519 public key. Every event signature, actor/key binding, sequence, previous hash, and recomputed hash is checked. Private keys in `keys/` void the bundle. `keys/delegation.json`, the fixed event types, and proof fields are specified in `EVIDENCE.md`.

`probes/boundary-ladder.json` must use format `molt-warden-probe-io/v1`, contain nonempty `cases`, and each case must have only `case_id`, `input`, and `output`. Vendor implementation/source is forbidden in Trial III. `attacks/poisoned-variant.json` must identify a poisoned input expected to abort; its exact bytes must match the signed proof-gate event.

## Hard rules

1. **No private keys.** Any private-key material under `keys/` makes the bundle VOID.
2. **Offline replay.** The grader disables network, provides only fixed environment values, and mounts bundle and fixture data read-only. The runner is non-root and resource-limited.
3. **Anchors are authority claims, not independent witnesses.** The verifier checks local anchor consistency; a local file is not external finality.
4. **Evidence is self-contained.** Disqualification evidence must refer to local files with matching SHA-256 digests. Signatures bind the claim to a key; they do not make the claim true.
5. **Probes are I/O only.** Trial III source files, including common script extensions, make the bundle VOID.
6. **No fabricated roots.** Any mismatch among the manifest, state-root file, and replay output makes the bundle VOID.
7. **`transcript.md` is ignored at every depth.** Any path component named `transcript.md` is excluded before metadata checks, evidence reads, MOLT artifact validation, and Docker staging.

## Trial-specific requirements

- **I:** genesis identity, ten distinct ruleset generations, hot-swap evidence, fitness-based selection, and a zero-violation signed audit.
- **II:** a 2-of-3 configuration, isolated malicious node, loss-free reconciliation, self-heal, and safe partition evidence; include one attack script for harness reruns.
- **III:** black-box boundary I/O and a poisoned proof-gate artifact. A fresh random liar ID is currently selected after bundle creation; the static offline bundle cannot attest that runtime ID. G3.1 remains fail-closed until a live challenge channel is specified.
- **IV:** at least three migrations with tombstone/resumption records, anchor-only reconstruction, monotone finality, a present twin store with replayable disqualification evidence, lineage horizon, epoch-2/3 policy evidence, and one attack script for harness reruns.
