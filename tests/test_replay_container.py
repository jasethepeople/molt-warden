from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from moltwarden.bundle import load_bundle
from moltwarden.replay import run_replay
from tests.helpers import make_bundle


PROJECT = Path(__file__).resolve().parents[1]


class DockerReplayTests(unittest.TestCase):
    def setUp(self):
        docker = shutil.which("docker")
        pin = PROJECT / "docker" / "image-id.txt"
        if not docker or not pin.is_file():
            self.skipTest("requires Docker and the locally pinned warden replay image")
        try:
            result = subprocess.run([docker, "info"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest("Docker daemon is unavailable")
        if result.returncode:
            self.skipTest("Docker daemon is unavailable")

    def test_twice_replay_is_root_matched_and_host_observed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle")
            (root / "replay.sh").write_text(
                "#!/bin/sh\nsleep 1\nprintf 'state_root %s\\n' \"$(cat /bundle/artifacts/state_root.txt)\"\n",
                encoding="ascii",
            )
            (root / "replay.sh").chmod(0o755)
            bundle = load_bundle(root)
            outcome = run_replay(bundle, str(PROJECT / "fixtures"))
            self.assertTrue(outcome.ok, outcome.reason)
            self.assertEqual(len(outcome.runs), 2)
            self.assertEqual(outcome.runs[0]["state_root"], outcome.runs[1]["state_root"])
            for run in outcome.runs:
                runtime = run["runtime"]
                self.assertEqual(runtime["host_sample_source"], "docker-stats-and-inspect")
                self.assertTrue(runtime["resource_samples"])
                self.assertTrue(runtime["trial_process_seen"])
                self.assertFalse(runtime["unattributed_process"])

    def test_attack_script_is_rerun_with_host_process_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_bundle(Path(temporary) / "bundle", trial="II")
            (root / "replay.sh").write_text(
                "#!/bin/sh\nsleep 1\nprintf 'state_root %s\\n' \"$(cat /bundle/artifacts/state_root.txt)\"\n",
                encoding="ascii",
            )
            attack = root / "attacks" / "test.sh"
            attack.write_text("#!/bin/sh\nsleep 1\nexit 0\n", encoding="ascii")
            bundle = load_bundle(root)
            outcome = run_replay(bundle, str(PROJECT / "fixtures"))
            self.assertTrue(outcome.ok, outcome.reason)
            self.assertEqual(len(outcome.attack_runs), 2)
            for run in outcome.attack_runs:
                runtime = run["runtime"]
                self.assertEqual(runtime["host_sample_source"], "docker-stats-and-inspect")
                self.assertTrue(runtime["resource_samples"])
                self.assertTrue(runtime["trial_process_seen"])
                self.assertFalse(runtime["unattributed_process"])


if __name__ == "__main__":
    unittest.main()
