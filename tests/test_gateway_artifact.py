"""Native archive smoke rejects changed or foreign payloads before execution."""

import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/smoke_gateway_artifact.py"
SPEC = importlib.util.spec_from_file_location("gateway_artifact", SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class GatewayArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sha = "a" * 40
        self.name = "ha-access-gateway-0.1.1-linux-arm64.tar.gz"
        with tarfile.open(self.root / self.name, "w:gz") as archive:
            member = tarfile.TarInfo("ha-access-gateway")
            member.size = 6
            archive.addfile(member, io.BytesIO(b"binary"))
        self.receipt = {
            "source_sha": self.sha,
            "files": [{"path": "version", "fields": [{"value": "0.1.1"}]}],
            "artifacts": [
                {
                    "name": self.name,
                    "size": (self.root / self.name).stat().st_size,
                    "sha256": hashlib.sha256((self.root / self.name).read_bytes()).hexdigest(),
                }
            ],
        }
        self.write_receipt()
        for name, value in (("system", "Linux"), ("machine", "aarch64")):
            p = patch.object(smoke.platform, name, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def write_receipt(self):
        (self.root / "release-inputs-distribution.json").write_text(json.dumps(self.receipt))

    def test_exact_archive_runs_only_version_and_help(self):
        def execute(args, **kwargs):
            self.assertEqual(kwargs["env"], {"PATH": smoke.os.defpath})
            self.assertEqual(Path(args[0]).read_bytes(), b"binary")
            return subprocess.CompletedProcess(
                args, 0, "0.1.1\n" if args[-1] == "--version" else "Usage: -config path\n"
            )

        with patch.object(smoke.subprocess, "run", side_effect=execute) as run:
            receipt = smoke.smoke(self.root, "arm64", self.sha)
        self.assertEqual([call.args[0][-1] for call in run.call_args_list], ["--version", "--help"])
        self.assertEqual(receipt["archive_sha256"], self.receipt["artifacts"][0]["sha256"])
        self.assertEqual(receipt["binary_sha256"], hashlib.sha256(b"binary").hexdigest())

    def test_frozen_pep440_beta_version_is_exercised(self):
        name = self.name.replace("0.1.1", "0.1.1b2")
        (self.root / self.name).rename(self.root / name)
        self.receipt["artifacts"][0]["name"] = name
        self.receipt["files"][0]["fields"][0]["value"] = "0.1.1b2"
        self.write_receipt()
        results = [
            subprocess.CompletedProcess([], 0, value) for value in ("0.1.1b2", "-config path")
        ]
        with patch.object(smoke.subprocess, "run", side_effect=results):
            result = smoke.smoke(self.root, "arm64", self.sha)
        self.assertEqual(result["version"], "0.1.1b2")

    def test_linked_binary_never_executes(self):
        with tarfile.open(self.root / self.name, "w:gz") as archive:
            member = tarfile.TarInfo("ha-access-gateway")
            member.type = tarfile.SYMTYPE
            member.linkname = "/bin/sh"
            archive.addfile(member)
        data = (self.root / self.name).read_bytes()
        self.receipt["artifacts"][0].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.write_receipt()
        with patch.object(smoke.subprocess, "run") as run, self.assertRaises(ValueError):
            smoke.smoke(self.root, "arm64", self.sha)
        run.assert_not_called()

    def test_changed_archive_never_executes(self):
        with (self.root / self.name).open("ab") as stream:
            stream.write(b"changed")
        with patch.object(smoke.subprocess, "run") as run, self.assertRaises(ValueError):
            smoke.smoke(self.root, "arm64", self.sha)
        run.assert_not_called()

    def test_wrong_source_never_executes(self):
        with patch.object(smoke.subprocess, "run") as run, self.assertRaises(ValueError):
            smoke.smoke(self.root, "arm64", "b" * 40)
        run.assert_not_called()

    def test_foreign_host_never_executes(self):
        with (
            patch.object(smoke.platform, "machine", return_value="x86_64"),
            patch.object(smoke.subprocess, "run") as run,
            self.assertRaises(ValueError),
        ):
            smoke.smoke(self.root, "arm64", self.sha)
        run.assert_not_called()

    def test_wrong_reported_version_fails(self):
        with (
            patch.object(
                smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "wrong")
            ),
            self.assertRaisesRegex(ValueError, "version/help"),
        ):
            smoke.smoke(self.root, "arm64", self.sha)


if __name__ == "__main__":
    unittest.main()
