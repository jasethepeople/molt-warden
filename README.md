# molt-warden

A fail-closed MOLT verification harness: it validates signed evidence, replays submissions in a sealed Docker container, runs the frozen criterion registry, and exercises synthetic anti-cheat cases.

**Status: v0.2.0 implementation; not GAUNTLET-certified.** The additive point-in-time bundle field is validated; all 27 criterion IDs and six invariants remain wired to executable checks. The checks implement the exact evidence profile in `EVIDENCE.md`; they do not invent meaning for unspecified GAUNTLET proof formats, and a signed claim is not treated as proof of factual truth. Trial III has a known static-bundle/runtime-liar mismatch; see `KNOWN-GAPS.md` before relying on G3.1.

## Build and test

Requirements: Python 3.11+, OpenSSL 3 for Ed25519 verification, and Docker on Linux/amd64 for isolated replay.

```sh
python3 -m pip install -e '.[test]'
python3 -m moltwarden fixtures build --v0
python3 -m moltwarden replay-image build
python3 -m unittest discover -s tests -v
```

The replay-image command builds the pinned Python base image, records the resulting local image ID in an ignored file, and refuses replay if that image later changes. Unit tests run without Docker; Docker integration tests skip unless the pinned image is built. A ready-to-enable workflow is included at `ci/github-actions.yml`. It could not be published under `.github/workflows/` because the connected GitHub token lacks the `workflow` permission, so remote CI has not run.

## Verify a bundle

```sh
python3 -m moltwarden verify /path/to/bundle --fixtures fixtures --output verdict.json
python3 -m moltwarden report verdict.json
python3 -m moltwarden redteam
```

The grader records the current clean Git commit automatically; an uncommitted tree is marked `uncommitted`. `--grader-commit` overrides it. Exit codes: `0` PASS, `1` FAIL, `2` VOID, `3` ERROR. Invalid bundles or failed/missing isolated replay are VOID; the grader never executes submissions unsandboxed.

Point-in-time submissions may add the optional `manifest.point_in_time` object documented in `BUNDLE.md`. Warden validates that the anchor event exists, rejects malformed or post-anchor stored events as VOID, and otherwise applies the unchanged trial profile and verdict schema.

## Replay and scoring

Each replay runs with no network, read-only bundle and fixture mounts, a read-only root filesystem, a non-root UID, dropped capabilities, no-new-privileges, a private IPC namespace, and limits of 512 MiB, two CPUs, 256 PIDs, and bounded output. The two `replay.sh` runs must produce identical roots matching `artifacts/state_root.txt`. Trials II and IV also run their single attack script twice. The 900-second budget covers every run in the trial. Host-observed Docker/process/resource telemetry feeds X3 and X6; missing telemetry fails closed.

Any `transcript.md` path component is skipped before file metadata checks, evidence reads, and Docker staging. Scoring opens contract-defined paths only; narration is not evidence.

## Fixtures

`fixtures/SEEDS.json` defines the deterministic `world-v0`, `vendors-v0`, and `twin-v0` scenarios. Generated fixture manifests and the seed file are pinned by digest and rechecked before replay and after staging. Trial III's liar ID is selected in grader memory and never added to the bundle or verdict. The current offline replay does not yet expose that random identity through a black-box oracle, so G3.1 cannot be reliably satisfied by a static submission; this limitation is explicit rather than papered over.

## Scope and trust

The verifier proves internal ledger integrity, key attribution, fixed-profile predicate checks, repeatability, and configured runtime limits. It does not prove that a signed assertion is true, that local anchors have an independent witness, or that a deterministic program is correct. See `EVIDENCE.md`, `SPEC.md`, `BUNDLE.md`, `KNOWN-GAPS.md`, and `docs/THREAT-MODEL.md` for the exact profile, contract, and residual risks.
