from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from moltwarden.bundle import load_bundle
from moltwarden.grader import grade
from moltwarden.invariants import _x3, _x6
from moltwarden.replay import ReplayOutcome
from moltwarden.verdict import Replay, Result, Verdict
from tests.helpers import make_bundle


class VerdictTests(unittest.TestCase):
    def test_round_trip_json_preserves_result(self):
        verdict = Verdict(
            warden_version="0.1.0", grader_commit="abc123", bundle_id="b", trial="I", fixture="world-v0",
            replay=Replay("PASS", "sha256:" + "a" * 64, 1.5, "ok"),
        )
        verdict.criteria.append(Result("G1.1", "PASS", "anchors/genesis.json"))
        restored = Verdict.from_json(verdict.to_json())
        self.assertEqual(restored.to_json(), verdict.to_json())

    def test_invalid_replay_is_void_not_failed_score(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            with patch("moltwarden.grader.run_replay", return_value=ReplayOutcome(False, "", 0.1, "no Docker")):
                verdict = grade(str(root), str(Path(temporary)))
            self.assertEqual(verdict.overall, "VOID")
            self.assertEqual(verdict.replay.status, "VOID")
            self.assertEqual(verdict.criteria, [])
            self.assertEqual(verdict.invariants, [])


class HostInvariantTests(unittest.TestCase):
    def _bundle(self, root: Path, runtime: dict, *, trial="I", attacks=None):
        bundle = load_bundle(make_bundle(root, trial=trial))
        run = {"duration_s": 1.0, "runtime": runtime, "state_root": bundle.state_root()}
        bundle.cache["replay_outcome"] = SimpleNamespace(
            ok=True, runs=[run, run], attack_runs=attacks or [], duration_s=2.0,
        )
        return bundle

    @staticmethod
    def _runtime():
        return {
            "host_sample_source": "docker-stats-and-inspect",
            "process_samples": 2,
            "runner_seen": True,
            "trial_process_seen": True,
            "unattributed_process": False,
            "process_tree": [{"pid": 1, "ppid": 0, "command": "warden"}],
            "resource_samples": [{"memory_bytes": 1024, "cpu_percent": 1.0, "pids": 2}],
            "oom_killed": False,
            "memory_limit_bytes": 512 * 1024 * 1024,
            "nano_cpus": 2_000_000_000,
            "pids_limit": 256,
        }

    def test_x3_requires_host_process_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self._bundle(Path(temporary) / "bundle", self._runtime())
            self.assertEqual(_x3(bundle).status, "PASS")
            bundle.cache["replay_outcome"].runs[0]["runtime"]["host_sample_source"] = "submitter-json"
            self.assertEqual(_x3(bundle).status, "FAIL")

    def test_x6_requires_host_limits_and_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self._bundle(Path(temporary) / "bundle", self._runtime())
            self.assertEqual(_x6(bundle).status, "PASS")
            bundle.cache["replay_outcome"].runs[0]["runtime"]["oom_killed"] = True
            self.assertEqual(_x6(bundle).status, "FAIL")

    def test_x3_and_x6_include_both_attack_reruns(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self._bundle(Path(temporary) / "bundle", self._runtime(), trial="II")
            attack = {"duration_s": 1.0, "runtime": self._runtime()}
            bundle.cache["replay_outcome"].attack_runs = [attack, attack]
            self.assertEqual(_x3(bundle).status, "PASS")
            self.assertEqual(_x6(bundle).status, "PASS")
            bundle.cache["replay_outcome"].attack_runs.pop()
            self.assertEqual(_x3(bundle).status, "FAIL")
            self.assertEqual(_x6(bundle).status, "FAIL")


if __name__ == "__main__":
    unittest.main()
