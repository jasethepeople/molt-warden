"""Verification orchestration. Replay is the scoring gate."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .bundle import BundleError, load_bundle
from .criteria import load_registry, run_criterion
from .fixtures import select_liar_identity
from .invariants import run_invariant
from .replay import ReplayOutcome, run_replay
from .verdict import Replay, Result, Verdict

WARDEN_VERSION = "0.2.0"
EXPECTED_CRITERIA = {"I": 6, "II": 7, "III": 7, "IV": 7}


def _void(grader_commit: str, bundle_id: str, trial: str, fixture: str, reason: str, duration: float = 0.0) -> Verdict:
    return Verdict(
        warden_version=WARDEN_VERSION,
        grader_commit=grader_commit,
        bundle_id=bundle_id,
        trial=trial,
        fixture=fixture,
        replay=Replay(status="VOID", duration_s=duration, reason=reason),
    ).finalize()


def _grader_revision() -> str:
    root = Path(__file__).resolve().parent.parent
    git = shutil.which("git")
    if not git:
        return "unknown"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
    try:
        revision = subprocess.run([git, "-C", str(root), "rev-parse", "--verify", "HEAD"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False, env=env, close_fds=True)
        status = subprocess.run([git, "-C", str(root), "status", "--porcelain", "--untracked-files=all"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False, env=env, close_fds=True)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    value = revision.stdout.decode("ascii", "replace").strip()
    if revision.returncode or status.returncode or not re.fullmatch(r"[0-9a-f]{40,64}", value):
        return "unknown"
    return value if not status.stdout.strip() else "uncommitted"


def grade(bundle_path: str, fixtures_dir: str, grader_commit: str | None = None) -> Verdict:
    grader_commit = grader_commit or _grader_revision()
    try:
        bundle = load_bundle(bundle_path)
    except BundleError as exc:
        return _void(grader_commit, "<unloadable>", "?", "?", str(exc))

    if bundle.trial == "III":
        bundle.cache["runtime_liar_id"] = select_liar_identity()
    try:
        outcome: ReplayOutcome = run_replay(bundle, fixtures_dir)
    except Exception as exc:
        return _void(grader_commit, bundle.id, bundle.trial, bundle.manifest["fixture"], f"replay runner error: {type(exc).__name__}: {exc}")

    replay = Replay(
        status="PASS" if outcome.ok else "VOID",
        state_root=outcome.state_root,
        duration_s=outcome.duration_s,
        reason=outcome.reason,
    )
    bundle.cache["replay_outcome"] = outcome
    verdict = Verdict(
        warden_version=WARDEN_VERSION,
        grader_commit=grader_commit,
        bundle_id=bundle.id,
        trial=bundle.trial,
        fixture=bundle.manifest["fixture"],
        replay=replay,
    )
    if replay.status != "PASS":
        return verdict.finalize()

    try:
        registry = load_registry(bundle.trial)
        if len(registry["criteria"]) != EXPECTED_CRITERIA[bundle.trial] or len(registry["invariants"]) != 6:
            raise RuntimeError("frozen criterion registry has an unexpected count")
        for criterion in registry["criteria"]:
            verdict.criteria.append(run_criterion(criterion, bundle))
        for invariant in registry["invariants"]:
            verdict.invariants.append(run_invariant(invariant, bundle))
    except Exception as exc:
        verdict.invariants.append(Result("X0", "FAIL", f"artifacts/verify.json: grader registry/orchestration error: {type(exc).__name__}: {exc}"))
    return verdict.finalize()
