"""Release channels must all pass the package's own consistency gate."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "package_version_check", Path(__file__).resolve().parents[1] / "scripts/check_version.py"
)
version_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version_check)


class VersionTest(unittest.TestCase):
    def test_toolkit_release_channels_and_mismatched_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "custom_components/ha_access_session/manifest.json"
            manifest.parent.mkdir(parents=True)
            for version in ("0.1.0", "0.1.0b2", "0.1.0rc1", "0.1.0.dev20261015"):
                (root / "version").write_text(version)
                manifest.write_text(json.dumps({"version": version}))
                (root / "pyproject.toml").write_text(f'[project]\nversion="{version}"\n')
                with self.subTest(version=version), redirect_stdout(io.StringIO()):
                    version_check.check(root)
            manifest.write_text('{"version":"0.0.0"}')
            with self.assertRaises(AssertionError):
                version_check.check(root)
        for version in ("0.1", "v0.1.0-beta.1", "0.1.0b", "0.1.0;echo bad"):
            self.assertFalse(version_check.valid_package_version(version))
