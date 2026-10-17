#!/usr/bin/env python3
"""Run only version/help paths of a hash-bound gateway archive on its native host."""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path


def smoke(staged: Path, architecture: str, source_sha: str) -> dict:
    """Reject wrong identity or changed bytes before executing the packaged binary."""
    machine = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
    if platform.system() != "Linux" or platform.machine() != machine:
        raise ValueError("Gateway smoke requires the matching native Linux host")
    receipt = json.loads((staged / "release-inputs-distribution.json").read_text())
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha) or receipt["source_sha"] != source_sha:
        raise ValueError("Gateway source differs from the producer commit")
    versions = [
        field["value"]
        for entry in receipt["files"]
        if entry["path"] == "version"
        for field in entry["fields"]
    ]
    if len(versions) != 1 or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+|\.dev[0-9]+)?", versions[0]
    ):
        raise ValueError("Expected one frozen package version")
    version = versions[0]
    name = f"ha-access-gateway-{version}-linux-{architecture}.tar.gz"
    assets = [asset for asset in receipt["artifacts"] if asset["name"] == name]
    if len(assets) != 1:
        raise ValueError("Gateway archive is not uniquely declared")
    archive = staged / name
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 32_000_000:
        raise ValueError("Expected a bounded regular gateway archive")
    payload = archive.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if len(payload) != assets[0]["size"] or digest != assets[0]["sha256"]:
        raise ValueError("Gateway archive digest differs from its producer receipt")
    with tarfile.open(archive) as package:
        binaries = []
        total_size = 0
        for count, member in enumerate(package, 1):
            total_size += member.size
            if count > 10000 or total_size > 64_000_000:
                raise ValueError("Gateway archive exceeds member bounds")
            if member.name == "ha-access-gateway":
                binaries.append(member)
        if len(binaries) != 1 or not binaries[0].isfile() or not 0 < binaries[0].size < 24_000_000:
            raise ValueError("Expected one bounded regular gateway binary")
        stream = package.extractfile(binaries[0])
        if stream is None:
            raise ValueError("Gateway payload is missing")
        binary = stream.read(24_000_001)
    if len(binary) != binaries[0].size:
        raise ValueError("Gateway binary length differs from archive metadata")
    with tempfile.TemporaryDirectory(prefix="gateway-native-smoke-") as directory:
        executable = Path(directory) / "ha-access-gateway"
        executable.write_bytes(binary)
        executable.chmod(0o700)
        outputs = {}
        for flag in ("--version", "--help"):
            result = subprocess.run(
                [str(executable), flag],
                cwd=directory,
                env={"PATH": os.defpath},
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
            outputs[flag] = result.stdout
        if outputs["--version"].strip() != version or "-config" not in outputs["--help"]:
            raise ValueError("Packaged gateway version/help contract differs")
    return {
        "schema": 1,
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "source_sha": source_sha,
        "architecture": architecture,
        "version": version,
        "archive": name,
        "archive_sha256": digest,
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "checks": ["native --version", "native --help"],
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", type=Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = smoke(args.staged, args.architecture, args.source_sha)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
