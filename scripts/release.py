"""Preview, tag, validate, or publish a Rugix release."""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "rugix/rugix"
TAG = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(alpha|beta|dev|rc)\.(0|[1-9][0-9]*))?"
)


@dataclass(frozen=True)
class Release:
    tag: str
    commit: str
    previous: str | None
    notes: str
    prerelease: bool


def plan_release(root: Path, tag: str, commit: str = "HEAD") -> Release:
    """Validate a release against ancestor tags and its committed changelog."""
    version = tag_key(tag)
    if version is None:
        raise ValueError(
            "Use vMAJOR.MINOR.PATCH, optionally followed by -alpha.N, -beta.N, -dev.N, or -rc.N"
        )
    commit = git(root, "rev-parse", f"{commit}^{{commit}}")
    if (
        tag in git(root, "tag", "--list").splitlines()
        and git(root, "rev-parse", f"{tag}^{{commit}}") != commit
    ):
        raise ValueError(f"Tag {tag} already points to a different commit")
    ancestors = git(root, "tag", "--merged", commit).splitlines()
    earlier = []
    for other in ancestors:
        key = tag_key(other)
        if key is None or other == tag:
            continue
        if key >= version:
            raise ValueError(
                f"Release {tag} must be newer than ancestor release {other}"
            )
        if not version[3] or key[3]:
            earlier.append(other)
    previous = max(earlier, key=tag_key, default=None)
    changelog = git(root, "show", f"{commit}:CHANGELOG.md")
    heading = f"Version {tag[1:]}"
    sections = re.split(r"(?m)^## ", changelog)
    matches = [
        section.partition("\n")[2].strip()
        for section in sections[1:]
        if section.split("\n", 1)[0] == heading
    ]
    if len(matches) != 1 or not matches[0]:
        raise ValueError(
            f"CHANGELOG.md must contain one nonempty '## {heading}' section"
        )
    return Release(tag, commit, previous, matches[0], not version[3])


def preview(root: Path, tag: str) -> None:
    release = plan_release(root, tag)
    print(f"Release {tag} of {release.commit}")
    print(f"Previous release: {release.previous or 'none'}")
    print(
        f"GitHub status: {'prerelease' if release.prerelease else 'latest stable release'}"
    )
    print(
        "Assets: Linux binaries and SBOMs, macOS Rugix Bundler archives, Debian packages"
    )
    print("        (excluding rugix-util), Debian source-package metadata, SHA256SUMS")
    print(f"\n{release.notes}\n")
    try:
        print(generated_notes(release))
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        print(
            f"GitHub PR notes unavailable; install/authenticate gh and push this commit: {error}"
        )


def push_tag(root: Path, tag: str) -> None:
    if git(root, "status", "--porcelain"):
        raise ValueError("Commit or stash all changes before tagging a release")
    git(root, "fetch", "--quiet", "origin", "main")
    if git(root, "rev-parse", "HEAD") != git(root, "rev-parse", "origin/main"):
        raise ValueError("Check out the latest commit of origin/main to release it")
    if tag in git(root, "tag", "--list").splitlines():
        raise ValueError(f"Tag {tag} already exists")
    plan_release(root, tag)
    git(root, "tag", "--annotate", tag, "--message", f"Release {tag}")
    git(root, "push", "origin", f"refs/tags/{tag}")
    print(f"Pushed {tag}. Follow https://github.com/{REPOSITORY}/actions")


def publish(root: Path, tag: str) -> None:
    """Resume drafts, publish after uploading all assets, and preserve published releases."""
    release = plan_release(root, tag, tag)
    if git(root, "rev-parse", "HEAD") != release.commit:
        raise ValueError("Publishing requires checking out the release tag")
    releases = gh(
        "api",
        "--paginate",
        f"repos/{REPOSITORY}/releases",
        "--jq",
        ".[] | {tag_name, draft} | @json",
    )
    existing = next(
        (
            item
            for line in releases.splitlines()
            if (item := json.loads(line))["tag_name"] == tag
        ),
        None,
    )
    if existing is not None and not existing["draft"]:
        print(f"Release {tag} is already published; leaving it unchanged")
        return
    assets = release_assets(root)
    notes = release.notes + "\n\n" + generated_notes(release)
    with tempfile.TemporaryDirectory() as temporary:
        notes_file = Path(temporary) / "notes.md"
        notes_file.write_text(notes)
        checksum_file = Path(temporary) / "SHA256SUMS"
        checksums = []
        for asset in assets:
            with asset.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            checksums.append(f"{digest}  {asset.name}\n")
        checksum_file.write_text("".join(checksums))
        if existing is None:
            args = [
                "release",
                "create",
                tag,
                "--repo",
                REPOSITORY,
                "--verify-tag",
                "--draft",
                "--title",
                tag,
                "--notes-file",
                str(notes_file),
            ]
            if release.prerelease:
                args += ["--prerelease"]
            gh(*args)
        else:
            gh(
                "release",
                "edit",
                tag,
                "--repo",
                REPOSITORY,
                "--notes-file",
                str(notes_file),
            )
        gh(
            "release",
            "upload",
            tag,
            "--repo",
            REPOSITORY,
            *(str(asset) for asset in assets),
            str(checksum_file),
            "--clobber",
        )
    gh(
        "release",
        "edit",
        tag,
        "--repo",
        REPOSITORY,
        "--draft=false",
        f"--prerelease={str(release.prerelease).lower()}",
        f"--latest={str(not release.prerelease).lower()}",
    )


def release_assets(root: Path) -> list[Path]:
    assets = []
    for directory in ("binaries", "debs", "source"):
        files = sorted(
            path
            for path in (root / "build" / directory).iterdir()
            if path.is_file() and not path.name.startswith("rugix-util-")
        )
        if not files:
            raise ValueError(f"No release assets in build/{directory}")
        assets.extend(files)
    if len({asset.name for asset in assets}) != len(assets):
        raise ValueError("Release assets must have unique filenames")
    return assets


def generated_notes(release: Release) -> str:
    fields = [f"tag_name={release.tag}", f"target_commitish={release.commit}"]
    if release.previous:
        fields.append(f"previous_tag_name={release.previous}")
    return gh(
        "api",
        f"repos/{REPOSITORY}/releases/generate-notes",
        "--jq",
        ".body",
        *(argument for field in fields for argument in ("-f", field)),
    )


def tag_key(tag: str) -> tuple | None:
    match = TAG.fullmatch(tag)
    if match is None:
        return None
    major, minor, patch, label, number = match.groups()
    return (
        int(major),
        int(minor),
        int(patch),
        label is None,
        label or "",
        int(number or 0),
    )


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def gh(*args: str) -> str:
    return subprocess.run(
        ["gh", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preview", "tag", "validate", "publish"])
    parser.add_argument("tag")
    args = parser.parse_args()
    try:
        if args.command in ("preview", "tag"):
            git(ROOT, "fetch", "--quiet", "--tags", "origin")
        if args.command == "preview":
            preview(ROOT, args.tag)
        elif args.command == "tag":
            push_tag(ROOT, args.tag)
        elif args.command == "validate":
            release = plan_release(ROOT, args.tag, args.tag)
            print(f"Validated {release.tag} of {release.commit}")
        else:
            publish(ROOT, args.tag)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
