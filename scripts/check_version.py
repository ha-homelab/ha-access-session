"""Enforce the release toolkit's PEP 440 package version across both components."""

import json
from pathlib import Path
import re
import tomllib


def valid_package_version(value):
    """Accept stable, beta, release candidate and nightly toolkit versions."""
    return re.fullmatch(r"\d+\.\d+\.\d+(?:(?:b|rc)\d+|\.dev\d+)?", value) is not None


def check(root):
    version = (root / "version").read_text().strip()
    assert valid_package_version(version), "Invalid release version"
    assert (
        json.loads((root / "custom_components/ha_access_session/manifest.json").read_text())[
            "version"
        ]
        == version
    )
    assert tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"] == version
    print("Version synchronized: " + version)


if __name__ == "__main__":
    check(Path(__file__).resolve().parents[1])
