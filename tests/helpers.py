from __future__ import annotations

import json
from pathlib import Path

ROOT = "sha256:" + "0" * 64


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def make_bundle(root: Path, *, trial: str = "I", transcript: bool = False) -> Path:
    for directory in ("anchors", "stores", "keys", "artifacts"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "artifacts" / "state_root.txt").write_text(ROOT + "\n", encoding="ascii")
    (root / "replay.sh").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    (root / "replay.sh").chmod(0o755)
    write_json(root / "manifest.json", {
        "bundle_id": "test-bundle",
        "trial": trial,
        "fixture": {"I": "world-v0", "II": "world-v0", "III": "vendors-v0", "IV": "twin-v0"}[trial],
        "claimed_state_root": ROOT,
    })
    if trial in {"II", "IV"}:
        if trial == "IV":
            write_json(root / "keys" / "delegation.json", {"format": "molt-warden-keychain/v1"})
        (root / "attacks").mkdir()
        (root / "attacks" / "test.sh").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        (root / "attacks" / "test.sh").chmod(0o755)
    if trial == "III":
        (root / "probes").mkdir()
        write_json(root / "probes" / "boundary-ladder.json", {
            "format": "molt-warden-probe-io/v1",
            "cases": [{"case_id": "boundary", "input": {"amount": 1000000}, "output": {"amount": "bad"}}],
        })
        (root / "attacks").mkdir()
        write_json(root / "attacks" / "poisoned-variant.json", {"poisoned": True, "expected": "abort"})
    if transcript:
        (root / "transcript.md").symlink_to("/etc/passwd")
    return root
