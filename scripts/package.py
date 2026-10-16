"""Build deterministic release archives from an explicit source allowlist."""

import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import zipfile

root = Path(__file__).resolve().parents[1]
dist = root / "dist"
version = (root / "version").read_text().strip()
root_files = {
    "README.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "RELEASING.md",
    ".release-policy.json",
    "version",
    "go.mod",
    "go.sum",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements-dev.lock",
    ".gitignore",
}
distribution_root_files = {
    "LICENSE",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "RELEASING.md",
    ".release-policy.json",
}
source_dirs = {
    "custom_components",
    "gateway",
    "cmd",
    "scripts",
    "tests",
    "examples",
    "docs",
    "licenses",
    ".github",
}
excluded = {"__pycache__", ".ruff_cache", ".DS_Store"}
files = sorted(
    p
    for p in root.rglob("*")
    if p.is_file()
    and not p.is_symlink()
    and (
        p.relative_to(root).parts[0] in source_dirs or p.relative_to(root).as_posix() in root_files
    )
    and not excluded.intersection(p.parts)
    and p.suffix != ".pyc"
)


# Include only reproducible browser-toolchain manifests, never installed npm caches.
files = sorted(
    set(files)
    | {
        p
        for p in root.glob("tools/browser-compatibility/playwright-*/package*.json")
        if p.is_file()
        and not p.is_symlink()
        and not any(parent.is_symlink() for parent in p.parents if parent.is_relative_to(root))
        and p.name in {"package.json", "package-lock.json"}
    }
)


def archive_tar(destination, entries):
    with destination.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, file, executable in entries:
                    data = file.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if executable else 0o644
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(data))


integration = [
    p
    for p in files
    if p.relative_to(root).parts[0] in {"custom_components", "licenses", "docs", "examples"}
    or p.relative_to(root).as_posix() in distribution_root_files
]
with zipfile.ZipFile(
    dist / f"ha-access-session-{version}.zip", "w", compression=zipfile.ZIP_DEFLATED
) as archive:
    for p in integration:
        info = zipfile.ZipInfo(p.relative_to(root).as_posix(), date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, p.read_bytes())
archive_tar(
    dist / f"ha-access-session-{version}-source.tar.gz",
    [
        (f"ha-access-session-{version}/" + p.relative_to(root).as_posix(), p, p.suffix == ".sh")
        for p in files
    ],
)
for architecture in ("amd64", "arm64"):
    entries = [
        ("ha-access-gateway", dist / "bin" / f"ha-access-gateway-linux-{architecture}", True)
    ]
    entries += [
        (p.relative_to(root).as_posix(), p, False)
        for p in files
        if p.relative_to(root).parts[0] in {"licenses", "docs", "examples"}
        or p.relative_to(root).as_posix() in distribution_root_files
    ]
    archive_tar(dist / f"ha-access-gateway-{version}-linux-{architecture}.tar.gz", entries)
archives = sorted(p for p in dist.iterdir() if p.suffix in {".gz", ".zip"} and version in p.name)
(dist / "SHA256SUMS").write_text(
    "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in archives)
)
print("Packaged " + str(len(archives)) + " release archives in dist/")
