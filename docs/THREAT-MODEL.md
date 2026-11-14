# Threat model and operational limits

## Trust boundary

The submitter controls the bundle manifest, replay script, signed ledger, probe inputs, attack script, and every claim in those files. A signature or internal hash chain proves attribution/integrity relative to its key, not factual truth. The warden controls its source and registry, pinned v0 fixtures, Docker configuration and observations, hidden per-grade liar selection, and verdict calculation. Docker Engine, the host kernel, OpenSSL, and the warden installation are trusted computing base.

Malformed or unsafe bundles are VOID before scoring. The replay image is pinned to a published Python base digest and locally pinned by image ID. Bundle and fixtures are copied to a private staging directory and mounted read-only. Containers have no network, no capabilities, no-new-privileges, non-root UID, read-only root, private IPC, fixed environment, tmpfs-only scratch, bounded output, 512 MiB memory, two CPU cores, 256 PIDs, and a shared 900-second budget. Trials II and IV run their declared attack script twice under the same controls; all trials run `replay.sh` twice. Every replay must emit the same `state_root` as the declared artifact.

Any path component named `transcript.md` is excluded before inventory metadata checks, evidence paths, MOLT artifact validation, trial-specific validation, and replay staging. Its type, size, contents, and hashes cannot affect acceptance.

X3 and X6 use host-side `docker top`, `docker stats`, and `docker inspect` data. The container cannot supply its own telemetry. Missing or malformed host observations fail closed; the warden never substitutes an unsandboxed run.

## Evidence interpretation

The implementation validates a bounded MOLT-CORE Camp 1 ledger and the evidence predicates in `EVIDENCE.md`. These schemas are an explicit v0.1 profile, not a claim that GAUNTLET independently specified every payload. A signed, internally consistent claim may still be false. Local anchor files are not independent witnesses. A replay that deterministically emits a wrong root is still wrong.

## Known attack limits

- Docker process snapshots are periodic and can miss a process that starts and exits between samples.
- Resource samples are periodic; kernel-enforced limits provide ceilings, but sampling is not a kernel audit trace.
- A bundle can fabricate a consistent history from genesis unless a trusted external witness supplies an expected checkpoint.
- A signer can knowingly sign false evidence; no local cryptographic check can establish real-world truth.
- The host, Docker daemon, kernel, OpenSSL, and checked-out warden source are trusted. A compromised host can falsify telemetry or execute different code.
- The v0 per-grade liar ID is held privately by the grader, but submitted bundles are static and offline. The current verifier compares a preexisting signed disqualification event against that freshly selected ID; it does not provide a live vendor-oracle channel to the submitted agent. G3.1 therefore cannot be reliably satisfied by an agent that does not know the ID in advance. This is a known architecture gap, not a hidden success claim.
- The evidence profile checks internal predicates, not every unstated GAUNTLET scenario detail. A full independent oracle and externally witnessed anchors remain future work.

See `KNOWN-GAPS.md` for the maintained issue list. Do not interpret PASS as an independent-witness guarantee or certification of factual truth.
