"""Keep main-push and release qualification complete when PR CI skips docs."""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ReleaseScopeContract(unittest.TestCase):
    def test_release_entry_always_requires_full_validation(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/release-pipeline.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        classifiers = [step for step in workflow["jobs"]["scope"]["steps"] if step.get("id") == "scope"]
        self.assertEqual(len(classifiers), 1, "Expected exactly one release scope classifier")
        self.assertEqual(classifiers[0]["env"]["FORCE_FULL"], "true")


if __name__ == "__main__":
    unittest.main()
