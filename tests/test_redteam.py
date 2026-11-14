from __future__ import annotations

import unittest

from moltwarden.redteam import run_redteam


class SyntheticCheatTests(unittest.TestCase):
    def test_every_frozen_cheat_reaches_its_expected_detector(self):
        results = run_redteam()
        self.assertEqual({row["cheat"] for row in results}, {"C1", "C2", "C3", "C4", "C5"})
        self.assertTrue(all(row["status"] == "PASS" for row in results), results)


if __name__ == "__main__":
    unittest.main()
