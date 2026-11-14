from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from moltwarden.fixtures import LIAR_POOL, build_fixtures, select_liar_identity


def inventory(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


class FixtureTests(unittest.TestCase):
    def test_v0_fixtures_are_repeatable(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "fixtures"
            build_fixtures(target)
            first = inventory(target)
            build_fixtures(target)
            self.assertEqual(first, inventory(target))
            self.assertTrue((target / "world-v0" / "manifest.json").is_file())
            self.assertTrue((target / "vendors-v0" / "liar.template.json").is_file())
            self.assertTrue((target / "twin-v0" / "fork-schedule.json").is_file())

    def test_runtime_liar_is_selected_only_from_the_fixed_pool(self):
        self.assertIn(select_liar_identity(), LIAR_POOL)
        template = Path(__file__).resolve().parents[1] / "fixtures" / "vendors-v0" / "liar.template.json"
        self.assertTrue(template.is_file())


if __name__ == "__main__":
    unittest.main()
