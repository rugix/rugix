"""Verify binary and source package versions, including Debian prerelease ordering."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]


def run(*args, **kwargs):
    return subprocess.run(
        args,
        check=True,
        text=True,
        capture_output=True,
        **kwargs,
    ).stdout.strip()


class PackageVersionTests(unittest.TestCase):
    def test_binary_and_source_prerelease(self):
        """A release tag overrides git describe and both package kinds sort before stable."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ("scripts", "packaging", "crates/apps/rugix-ctrl/assets"):
                shutil.copytree(PROJECT / directory, root / directory)
            for name in ("Cargo.lock", "LICENSE-MIT", "LICENSE-APACHE", "README.md"):
                shutil.copy(PROJECT / name, root / name)
            run("git", "init", "-q", str(root))
            run(
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "Fixture",
            )
            run("git", "-C", str(root), "tag", "v1.4.0")
            binaries = root / "build/binaries/x86_64-unknown-linux-musl"
            binaries.mkdir(parents=True)
            (binaries / "rugix-bundler").write_text("#!/bin/sh\nexit 0\n")
            environment = dict(os.environ, RUGIX_GIT_VERSION="v1.5.0-rc.1")
            run("bash", str(root / "scripts/build-debs.sh"), env=environment)
            run("bash", str(root / "scripts/build-source-package.sh"), env=environment)
            package = next((root / "build/debs").glob("*.deb"))
            version = run("dpkg-deb", "-f", str(package), "Version")
            self.assertEqual(version, "1.5.0~rc.1")
            source = root / "build/source/rugix-debian_1.5.0~rc.1.dsc"
            self.assertIn("Version: 1.5.0~rc.1", source.read_text())
            run("dpkg", "--compare-versions", version, "lt", "1.5.0")
            for git_version, expected in (
                ("v1.5.0", "1.5.0"),
                ("v1.5.0-12-gabcdef", "1.5.0+12.gabcdef"),
                ("v1.5.0-rc.1-12-gabcdef", "1.5.0~rc.1+12.gabcdef"),
            ):
                environment["RUGIX_GIT_VERSION"] = git_version
                environment["PROJECT_DIR"] = str(root)
                converted = run(
                    "bash",
                    "-c",
                    'source "$PROJECT_DIR/scripts/debian-version.sh"; rugix_debian_version',
                    env=environment,
                )
                self.assertEqual(converted, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
