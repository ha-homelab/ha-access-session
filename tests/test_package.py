"""A downloaded integration must include the files needed for documented setup."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


class PackageTest(unittest.TestCase):
    def test_integration_archive_contains_installation_examples_and_component(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = (
                "scripts/package.py",
                "version",
                "README.md",
                "LICENSE",
                "THIRD_PARTY_NOTICES.md",
                "custom_components/ha_access_session/__init__.py",
                "custom_components/ha_access_session/access.py",
                "custom_components/ha_access_session/manifest.json",
                "docs/installation.md",
                "examples/configuration.yaml",
                "examples/gateway.json",
            )
            for name in files:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / name, target)
            (root / "dist/bin").mkdir(parents=True)
            for architecture in ("amd64", "arm64"):
                (root / "dist/bin" / f"ha-access-gateway-linux-{architecture}").write_bytes(
                    b"synthetic packaging fixture"
                )
            subprocess.run(
                [sys.executable, str(root / "scripts/package.py")],
                check=True,
                capture_output=True,
            )
            version = (root / "version").read_text().strip()
            with zipfile.ZipFile(root / "dist" / f"ha-access-session-{version}.zip") as archive:
                for name in files:
                    if name not in {"scripts/package.py", "version"}:
                        self.assertEqual(archive.read(name), (root / name).read_bytes())
