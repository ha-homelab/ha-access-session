"""Downloaded archives must contain setup files and linked documentation."""

import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from urllib.parse import unquote, urlsplit


def markdown_links(text):
    """Collect rendered links, excluding fenced Markdown examples."""
    rendered = []
    fence = None
    for line in text.splitlines():
        if fence is not None:
            closing = rf" {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*"
            if re.fullmatch(closing, line):
                fence = None
            continue
        opening = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if opening and not (opening[1][0] == "`" and "`" in opening[2]):
            fence = opening[1]
            continue
        rendered.append(line)
    prose = "\n".join(rendered)
    links = re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", prose)
    links += re.findall(r"(?m)^\s{0,3}\[[^\]]+\]:\s*(\S+)", prose)
    return links


class PackageTest(unittest.TestCase):
    def test_link_inventory_ignores_fenced_examples_but_keeps_real_links(self):
        document = (
            "[visible](installation.md)\n"
            "```markdown\n"
            "[example](docs/fuzzing.md)\n"
            "[reference-example]: absent.md\n"
            "````\n"
            "~~~markdown\n"
            "[another-example](absent.md)\n"
            "```\n"
            "[still-literal](also-absent.md)\n"
            "~~~\n"
            "![visible image](diagram.svg)\n"
            "[actual-missing-link](missing.md)\n"
            "[reference]: security.md\n"
        )
        self.assertEqual(
            markdown_links(document),
            ["installation.md", "diagram.svg", "missing.md", "security.md"],
        )

    def test_distribution_archives_include_installation_and_linked_documentation(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Use the real documentation, including transitive release-policy
            # links. Dummy executables keep this an offline packaging test.
            files = [
                "scripts/package.py",
                "version",
                "LICENSE",
                ".release-policy.json",
                *(path.name for path in source.glob("*.md")),
            ]
            toolchain_manifests = {
                path.relative_to(source).as_posix()
                for path in source.glob("tools/browser-compatibility/playwright-*/package*.json")
                if path.name in {"package.json", "package-lock.json"}
            }
            self.assertEqual(len(toolchain_manifests), 6)
            files.extend(sorted(toolchain_manifests))
            for name in files:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / name, target)
            for folder in ("custom_components", "docs", "examples", "licenses", ".github"):
                shutil.copytree(
                    source / folder,
                    root / folder,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
            toolchain = root / "tools/browser-compatibility/playwright-1-64-0"
            (toolchain / "node_modules/playwright").mkdir(parents=True)
            (toolchain / "node_modules/playwright/package.json").write_text("{}")
            (toolchain / "package-private.json").write_text("{}")
            alias = root / "toolchain-alias"
            alias.mkdir()
            (alias / "package.json").write_text("{}")
            (toolchain.parent / "playwright-linked").symlink_to(alias, target_is_directory=True)
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
                for name in (
                    "custom_components/ha_access_session/manifest.json",
                    "custom_components/ha_access_session/access.py",
                    "examples/configuration.yaml",
                    "examples/gateway.json",
                    "docs/installation.md",
                ):
                    self.assertEqual(archive.read(name), (root / name).read_bytes())
                self.assert_documentation_links(
                    archive.filename,
                    set(archive.namelist()),
                    {
                        name: archive.read(name)
                        for name in archive.namelist()
                        if name.endswith(".md")
                    },
                )
            for path in sorted((root / "dist").glob("*.tar.gz")):
                with tarfile.open(path) as archive:
                    if path.name.endswith("-source.tar.gz"):
                        prefix = f"ha-access-session-{version}/"
                        packaged_toolchains = {
                            name.removeprefix(prefix)
                            for name in archive.getnames()
                            if name.startswith(prefix + "tools/")
                        }
                        self.assertEqual(packaged_toolchains, toolchain_manifests)
                    self.assert_documentation_links(
                        path.name,
                        set(archive.getnames()),
                        {
                            member.name: archive.extractfile(member).read()
                            for member in archive.getmembers()
                            if member.isfile() and member.name.endswith(".md")
                        },
                    )

    def assert_documentation_links(self, archive, names, documents):
        for name, data in documents.items():
            # Fragments are navigation within a packaged file. Fenced examples
            # are literal text and do not create links in rendered Markdown.
            for link in markdown_links(data.decode("utf-8")):
                parsed = urlsplit(link.strip("<>"))
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(name), unquote(parsed.path))
                )
                with self.subTest(archive=archive, document=name, link=link):
                    self.assertIn(target, names, f"Missing packaged link target: {target}")
