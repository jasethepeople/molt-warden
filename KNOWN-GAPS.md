# Known gaps and limits

An open item is not repaired by a passing unit test. Keep unresolved limitations visible until they are fixed and covered by an end-to-end adversarial test.

| # | Gap | Impact | Status |
|---|---|---|---|
| 1 | Local anchors have no external witness | A self-consistent forged anchor cannot prove publication time or independent custody. X1 checks only internal linkage. | Open |
| 2 | Two colluding nodes defeat a 2-of-3 assumption | The verifier cannot detect a majority that is Byzantine. | Open; model assumption |
| 3 | Deterministic replay can still be wrong | X2 proves repeatability and root equality, not semantic correctness of the application. | Open |
| 4 | Signed MOLT claims can be false | Ed25519 proves key attribution and ledger integrity, not the truth of the signed payload. | Open |
| 5 | No independent GAUNTLET oracle was supplied | The 27 evidence predicates are executable, but scenario truth and some domain-specific event semantics are not independently witnessed. A criterion PASS is a profile match, not GAUNTLET certification. | Open |
| 6 | Trial III hidden liar identity is incompatible with static evidence | The grader selects the identity after the bundle is fixed, keeps it host-side, and does not inject a live oracle/result channel into the offline replay. The static signed event cannot reliably identify that fresh value; G3.1 is not generally passable. | Open; architecture blocker |
| 7 | Process-tree observation is sampled | A process that starts and exits between Docker `top` samples can evade X3. This is not a kernel execution trace. | Open |
| 8 | Fixture authenticity is local to this source revision | Seed and fixture manifest digests prevent accidental or casual mutation, but a party that changes warden source and its pinned digests can redefine fixtures. The grader source/commit and host remain trusted. | Open |
| 9 | File names can affect bundle safety, though not criterion selection | Scoring reads fixed contract paths; bundle validation still inspects names and extensions for safety, trial shape, and Trial III source rejection. | Partially mitigated |
| 10 | No real submission or full end-to-end PASS has been validated | The synthetic red-team suite exercises signed evidence predicates. Docker is unavailable locally. The CI workflow template is included, but the connected GitHub token lacks the `workflow` scope, so it is not active remotely yet. | Open until CI is enabled and real-world validation |

## Patched scaffold gaps

- Fixture trees are size- and file-count-bounded, checked against per-version manifests pinned in warden code, rechecked after staging, and mounted read-only.
- Any `transcript.md` path component is skipped before metadata inspection and excluded from evidence/MOLT artifact validation and replay copies. It is not an allowed evidence path.
- Private-key markers and unsupported file types under `keys/` make a bundle VOID; MOLT event signatures and declared key delegations are verified cryptographically.
- Docker absence, wrong image ID, missing host telemetry, failed replay, or resource/output-limit violation never triggers an unsandboxed fallback.

`LEDGER.md` records which synthetic cheats were observed to reach their intended criterion detector. Synthetic detector tests do not close the oracle, hidden-identity, process-sampling, or full-submission gaps above.
