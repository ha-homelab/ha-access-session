"""Check real release notes before builds reach the publication transaction."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "project_release_notes", ROOT / "scripts/release_control.py"
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseNotesContractTest(unittest.TestCase):
    def test_current_changelog_can_publish_every_candidate_channel(self):
        raw = (ROOT / "CHANGELOG.md").read_bytes()
        source = "a" * 40
        response = {
            "type": "file",
            "path": "CHANGELOG.md",
            "encoding": "base64",
            "content": base64.b64encode(raw).decode(),
            "size": len(raw),
            "sha": hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw,
                usedforsecurity=False,
            ).hexdigest(),
        }
        policy = json.loads((ROOT / ".release-policy.json").read_text())
        version = (ROOT / "version").read_text().strip()
        for suffix in ("-beta.1", "-beta.99", "-rc.1", ""):
            with self.subTest(channel=suffix):
                github = Mock()
                github.api.return_value = response
                with patch.object(release, "source_policy_snapshot", return_value={"data": policy}):
                    notes = release.release_notes(
                        github, f"v{version}{suffix}", source, "Build evidence."
                    )
                self.assertIn("### Upgrade", notes)
                self.assertIn("### Security", notes)
                self.assertIn("Build evidence.", notes)
                github.api.assert_called_once_with(f"contents/CHANGELOG.md?ref={source}")
