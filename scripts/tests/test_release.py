"""Exercise release planning, guarded tagging, and publication without remote writes."""

import contextlib
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "scripts"))
import release


def run(*args, **kwargs):
    return subprocess.run(
        args,
        check=True,
        text=True,
        capture_output=True,
        **kwargs,
    ).stdout.strip()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "test@example.com")
        self.commit("v1.4.0")
        self.git("tag", "v1.4.0")
        self.commit("v1.5.0-dev.2")
        self.git("tag", "v1.5.0-dev.2")
        self.commit("v1.5.0")
        self.commands = []
        self.existing = None
        self.fail_upload = False

    def git(self, *args):
        return run("git", "-C", str(self.root), *args)

    def commit(self, tag):
        changelog = self.root / "CHANGELOG.md"
        old = changelog.read_text() if changelog.exists() else "# Changelog\n"
        changelog.write_text(
            f"# Changelog\n\n## Version {tag[1:]}\n\nChanges for {tag}.\n\n" + old
        )
        self.git("add", ".")
        self.git("commit", "-qm", tag)

    def gh(self, *args):
        self.commands.append(args)
        if args[:2] == ("api", "--paginate"):
            return json.dumps(self.existing) if self.existing else ""
        if args[0] == "api":
            return "## What's Changed\n\nMerged pull requests."
        if args[:2] == ("release", "upload"):
            if self.fail_upload:
                raise subprocess.CalledProcessError(1, args)
            paths = [Path(arg) for arg in args[5:-1]]
            self.assertTrue(all(path.is_file() for path in paths))
            checksums = paths[-1].read_text().splitlines()
            self.assertEqual(len(checksums), len(paths) - 1)
            for asset, line in zip(paths[:-1], checksums):
                self.assertEqual(
                    line,
                    f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}",
                )
        return ""

    def assets(self):
        for directory, name in (
            ("binaries", "binaries-x86_64-unknown-linux-musl.tar"),
            ("debs", "rugix-ctrl-musl_1.5.0_amd64.deb"),
            ("source", "rugix-debian_1.5.0.dsc"),
        ):
            path = self.root / "build" / directory / name
            path.parent.mkdir(parents=True)
            path.write_text("release fixture")
        (self.root / "build/debs/rugix-util-musl_1.5.0_amd64.deb").write_text(
            "excluded"
        )

    def test_preview_and_stable_baseline(self):
        """Preview uses committed notes, skips prereleases as the stable baseline, and writes nothing."""
        with (
            patch.object(release, "gh", self.gh),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            release.preview(self.root, "v1.5.0")
        self.assertIn("Previous release: v1.4.0", output.getvalue())
        self.assertIn("Changes for v1.5.0.", output.getvalue())
        self.assertIn("Merged pull requests.", output.getvalue())
        self.assertIn("previous_tag_name=v1.4.0", self.commands[0])
        self.assertFalse(self.git("status", "--porcelain"))
        self.assertNotIn("v1.5.0", self.git("tag").splitlines())

    def test_prerelease_and_numeric_order(self):
        """Prereleases compare numeric identifiers numerically and use preceding prereleases for notes."""
        self.commit("v1.5.0-dev.10")
        planned = release.plan_release(self.root, "v1.5.0-dev.10")
        self.assertTrue(planned.prerelease)
        self.assertEqual(planned.previous, "v1.5.0-dev.2")
        with self.assertRaisesRegex(ValueError, "newer"):
            release.plan_release(self.root, "v1.5.0-dev.1")

    def test_invalid_release_preparation(self):
        """Malformed, backwards, missing-note, and duplicate-note releases fail planning."""
        for tag in (
            "v01.5.0",
            "v1.5",
            "v1.5.0-dev.01",
            "2026.11.18",
            "--help",
            "v1.3.0",
            "v1.4.0",
            "v1.6.0",
        ):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.plan_release(self.root, tag)
        self.commit("v1.5.0")
        with self.assertRaisesRegex(ValueError, "one nonempty"):
            release.plan_release(self.root, "v1.5.0")

    def test_guarded_tag_push(self):
        """Only a clean, latest main commit can create and push an annotated release tag."""
        remote = Path(self.temporary.name) / "remote.git"
        run("git", "init", "--bare", "-q", str(remote))
        self.git("remote", "add", "origin", str(remote))
        self.git("push", "-q", "origin", "main", "--tags")
        (self.root / "dirty").touch()
        with self.assertRaisesRegex(ValueError, "stash"):
            release.push_tag(self.root, "v1.5.0")
        (self.root / "dirty").unlink()
        head = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "HEAD~1")
        with self.assertRaisesRegex(ValueError, "latest"):
            release.push_tag(self.root, "v1.5.0")
        self.git("checkout", "-q", head)
        release.push_tag(self.root, "v1.5.0")
        self.assertEqual("tag", self.git("cat-file", "-t", "v1.5.0"))
        self.assertIn("refs/tags/v1.5.0", run("git", "ls-remote", str(remote)))
        with self.assertRaisesRegex(ValueError, "already exists"):
            release.push_tag(self.root, "v1.5.0")

    def test_publication_and_retry(self):
        """Failed uploads leave a draft; retries resume it, and published releases are untouched."""
        self.git("tag", "v1.5.0")
        self.assets()
        with patch.object(release, "gh", self.gh):
            self.fail_upload = True
            with self.assertRaises(subprocess.CalledProcessError):
                release.publish(self.root, "v1.5.0")
            self.assertTrue(
                any(
                    command[:2] == ("release", "create") and "--draft" in command
                    for command in self.commands
                )
            )
            self.assertFalse(
                any("--draft=false" in command for command in self.commands)
            )
            self.commands.clear()
            self.existing = {"tag_name": "v1.5.0", "draft": True}
            self.fail_upload = False
            release.publish(self.root, "v1.5.0")
            self.assertFalse(
                any(command[:2] == ("release", "create") for command in self.commands)
            )
            self.assertIn("--latest=true", self.commands[-1])
            upload = next(
                command
                for command in self.commands
                if command[:2] == ("release", "upload")
            )
            self.assertFalse(any("rugix-util" in arg for arg in upload))
            self.commands.clear()
            self.existing["draft"] = False
            release.publish(self.root, "v1.5.0")
            self.assertEqual(len(self.commands), 1)

    def test_prerelease_publication_and_failures(self):
        """Prereleases never become latest; failed lookups or missing assets cannot publish."""
        self.commit("v1.5.0-rc.1")
        self.git("tag", "v1.5.0-rc.1")
        with (
            patch.object(
                release, "gh", side_effect=subprocess.CalledProcessError(1, "gh")
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            release.publish(self.root, "v1.5.0-rc.1")
        with patch.object(release, "gh", self.gh):
            with self.assertRaises(FileNotFoundError):
                release.publish(self.root, "v1.5.0-rc.1")
            self.assets()
            release.publish(self.root, "v1.5.0-rc.1")
        self.assertIn("--latest=false", self.commands[-1])
        self.assertIn("--prerelease=true", self.commands[-1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
