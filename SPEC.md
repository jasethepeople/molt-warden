# SPEC — molt-warden v0.1

## 1. Scope

Grades bundles produced by MOLT agents against the 27 criteria and 6 cross-trial invariants of the GAUNTLET. Never grades narration.

## 2. Bundle contract

A bundle is valid only if it satisfies every rule in BUNDLE.md. Validation precedes scoring; an invalid bundle is VOID, not FAIL.

## 3. Replay contract (the gate)

`replay.sh` is executed as:

```sh
docker run --rm --network=none \
  -v <bundle>:/bundle:ro -v <fixtures>:/fixtures:ro \
  warden-replay:v0 /bundle/replay.sh
```

Preconditions:
- no network
- bundle and fixtures mounted read-only
- no host env beyond PATH, LANG, TZ=UTC
- wall-clock budget: 900s (VOID on exceed)
- invoked **twice**; both runs must agree

Success iff:
- exit code 0,
- stdout's final line is `state_root sha256:<64 hex>`,
- that hash equals `artifacts/state_root.txt`,
- and run 2's hash equals run 1's.

Any failure ⇒ bundle VOID. No criterion is scored. This is intentional: an unreplayable bundle cannot be graded without trusting the submitter.

## 4. Verdict contract

`verdict.json`:

```json
{
  "warden_version": "0.1.0",
  "grader_commit": "<sha>",
  "bundle_id": "<from manifest>",
  "trial": "I|II|III|IV",
  "fixture": "<version>",
  "replay": { "status": "PASS|VOID", "state_root": "...", "duration_s": 0 },
  "criteria": [ { "id": "G1.1", "status": "PASS|FAIL|SKIP", "reason": "<cited evidence path>" } ],
  "invariants": [ { "id": "X3", "status": "PASS|FAIL", "reason": "<cited evidence path>" } ],
  "overall": "PASS|FAIL|VOID"
}
```

Rules:
- every FAIL carries a `reason` that names a path inside the bundle,
- any X-invariant FAIL voids the trial regardless of criteria,
- `overall` is PASS only if replay PASS, all criteria PASS, all invariants PASS.

## 5. Isolation rules (grader-side, non-negotiable)

- grader runs sealed; it does not source the submitter's venv, PATH, or config
- X3: diff the sealed container's process tree against the harness's own; any trial logic not authored by the submitter ⇒ FAIL
- X6: resource log is the grader's (cgroup / /proc sampling), never the submitter's
- fixtures are content-addressed; identity of the liar vendor is injected at run time from the harness, never read from the bundle

## 6. Scoring

27 criteria, binary. Trial clear = all criteria in that trial PASS and no X-invariant FAIL. Gauntlet clear = four trials clear. No partial credit within a criterion.
