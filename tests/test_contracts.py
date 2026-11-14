from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from moltwarden.bundle import Bundle
from moltwarden.criteria import load_registry
from moltwarden.grader import EXPECTED_CRITERIA, grade
from moltwarden.invariants import run_invariant
from moltwarden.molt import MoltError, canonical_json
from moltwarden.verdict import Replay, Result, Verdict
from tests.helpers import make_bundle


PROJECT = Path(__file__).resolve().parents[1]


class RegistryTests(unittest.TestCase):
    def test_frozen_registry_has_27_criteria_and_6_invariants(self):
        registry = json.loads((PROJECT / "moltwarden" / "criteria.json").read_text())
        self.assertEqual(len(registry["criteria"]), 27)
        self.assertEqual(len(registry["invariants"]), 6)
        for trial, expected in EXPECTED_CRITERIA.items():
            loaded = load_registry(trial)
            self.assertEqual(len(loaded["criteria"]), expected)
            self.assertEqual(len(loaded["invariants"]), 6)

    def test_unknown_criterion_fails_closed(self):
        result = __import__("moltwarden.criteria", fromlist=["run_criterion"]).run_criterion(
            {"id": "G9.9", "trial": "I", "check": "missing"},
            Bundle(Path("/nonexistent"), {"bundle_id": "x", "trial": "I", "fixture": "world-v0"}),
        )
        self.assertEqual(result.status, "FAIL")
        self.assertIn("unknown criterion", result.reason)


class CanonicalizationTests(unittest.TestCase):
    def test_ascii_json_is_sorted_and_compact(self):
        self.assertEqual(canonical_json({"z": 1, "a": [True, None, "x"]}), '{"a":[true,null,"x"],"z":1}')

    def test_ecmascript_number_boundaries(self):
        self.assertEqual(canonical_json(1e-6), "0.000001")
        self.assertEqual(canonical_json(1e-7), "1e-7")
        self.assertEqual(canonical_json(1e21), "1e+21")
        self.assertEqual(canonical_json(-0.0), "0")

    def test_unsupported_values_fail_closed(self):
        with self.assertRaises(MoltError):
            canonical_json("caf\N{LATIN SMALL LETTER E WITH ACUTE}")
        with self.assertRaises(MoltError):
            canonical_json(float("inf"))
        with self.assertRaises(MoltError):
            canonical_json(9_007_199_254_740_992)


class VerdictTests(unittest.TestCase):
    def test_any_invariant_failure_voids_trial(self):
        verdict = Verdict(
            warden_version="0.1.0", grader_commit="abc", bundle_id="b", trial="I", fixture="world-v0",
            replay=Replay("PASS", "sha256:" + "0" * 64),
            criteria=[Result("G1.1", "PASS")], invariants=[Result("X3", "FAIL", "replay.sh: process diff")],
        ).finalize()
        self.assertEqual(verdict.overall, "VOID")

    def test_round_trip_json(self):
        original = Verdict(
            warden_version="0.1.0", grader_commit="abc", bundle_id="b", trial="I", fixture="world-v0",
            replay=Replay("VOID", reason="Docker unavailable"),
        )
        restored = Verdict.from_json(original.to_json())
        self.assertEqual(restored.to_json(), original.to_json())


class GraderGateTests(unittest.TestCase):
    def test_failed_replay_never_scores(self):
        with __import__("tempfile").TemporaryDirectory() as temporary:
            path = make_bundle(Path(temporary) / "bundle")
            outcome = __import__("moltwarden.replay", fromlist=["ReplayOutcome"]).ReplayOutcome(
                False, "", 0.1, "Docker unavailable",
            )
            with patch("moltwarden.grader.run_replay", return_value=outcome):
                verdict = grade(str(path), "unused")
            self.assertEqual(verdict.overall, "VOID")
            self.assertEqual(verdict.replay.status, "VOID")
            self.assertEqual(verdict.criteria, [])
            self.assertEqual(verdict.invariants, [])

    def test_x6_uses_only_host_owned_budget_telemetry(self):
        with __import__("tempfile").TemporaryDirectory() as temporary:
            path = make_bundle(Path(temporary) / "bundle")
            bundle = Bundle(path, {"bundle_id": "test", "trial": "I", "fixture": "world-v0"})
            runtime = {
                "host_sample_source": "docker-stats-and-inspect", "resource_samples": [
                    {"memory_bytes": 4096, "cpu_percent": 2.5, "pids": 2},
                ], "oom_killed": False, "memory_limit_bytes": 512 * 1024 * 1024,
                "nano_cpus": 2_000_000_000, "pids_limit": 256,
            }
            class Outcome:
                ok = True
                duration_s = 1.0
                runs = [{"runtime": runtime, "duration_s": 0.5}, {"runtime": runtime, "duration_s": 0.5}]
                attack_runs = []
            bundle.cache["replay_outcome"] = Outcome()
            spec = {"id": "X6", "check": "x6_budget_honesty"}
            self.assertEqual(run_invariant(spec, bundle).status, "PASS")
            runtime["host_sample_source"] = "submitter-log"
            self.assertEqual(run_invariant(spec, bundle).status, "FAIL")


if __name__ == "__main__":
    unittest.main()
