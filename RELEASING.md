# Releasing Rugix

Pushing a release tag runs the Build workflow. It runs formatting, lint, dependency,
unit, packaging, and system-test checks and builds Linux binaries, macOS Rugix
Bundler archives, Debian packages, and Debian source-package metadata. All checks
and builds must succeed before CI creates a draft GitHub release. CI uploads the
assets and `SHA256SUMS`, then publishes the release automatically.

Release tags use `vMAJOR.MINOR.PATCH`. Prereleases add `-alpha.N`, `-beta.N`,
`-dev.N`, or `-rc.N`, for example `v1.5.0-rc.1`. CI marks these as GitHub
prereleases and leaves the latest stable release unchanged. Debian packages use
`~` before the prerelease suffix so that upgrading to the stable version works.

## Prepare and Preview

Choose the version based on the changes being released. In `CHANGELOG.md`, move
the changes from `Unreleased` into a matching heading, for example
`## Version 1.5.0`, and leave an empty `Unreleased` section for future changes.
For a prerelease, use the full version in the heading, such as
`## Version 1.5.0-rc.1`. Commit the preparation and merge it into `main`.

From the checked-out release commit, preview the release. For example:

```sh
mise run release:preview v1.5.0
```

The preview fetches tags, checks the version and committed changelog section, and
shows the commit, previous release, asset categories, and release notes. It does
not create a tag or release. Stable releases compare against the highest earlier
stable version in the commit's ancestry; prereleases also consider earlier
prereleases. A release must be newer than every release tag in its ancestry.

Notes contain the matching changelog section followed by GitHub's list of merged
pull requests. That list requires an authenticated GitHub CLI and a commit pushed
to GitHub. If generating the PR list fails, the preview still shows the local plan
and explains why the PR list is missing; publication requires both parts of the notes.

For a build dry run, manually run the Build workflow on the release commit's
branch, such as `main`, with `publish` left false. It runs all checks and builds without creating or
changing a GitHub release. Its binaries report the commit's Git-derived version;
the final tag build reports the exact release tag.

## Publish

Check out the latest `origin/main` commit with a clean working tree. To release,
for example, version 1.5.0:

```sh
mise run release:tag v1.5.0
```

The task fetches tags and `main`, performs the release validation, creates an
annotated tag, and pushes only that tag. It refuses an existing tag, uncommitted
changes, or a checkout behind `origin/main`. The release version comes from the
tag; no Cargo package version bump is needed.

Watch the Build workflow until Publish Release succeeds. Check the notes and
downloaded assets before announcing the release. Binary archive names remain
unchanged, including the stable names used by download URLs. Linux archives
include SBOMs. The `rugix-util` Debian packages are excluded from releases.
The Debian source package contains packaging metadata and dependency information;
it is not a buildable copy of the Rugix sources.

## Recover a Failed Release

If a check or build fails, rerun the failed jobs after resolving the cause.
If the tagged sources need changes, prepare a new version and tag.

An upload failure leaves a draft release. Rerun the failed publishing job, or
manually run Build on the same release tag with `publish` set to true. For example:

```sh
gh workflow run build.yml --ref v1.5.0 -f publish=true
```

CI resumes the draft, replaces its asset files, and publishes only after all
uploads succeed.
Publishing runs for the same tag are serialized. A published release is left
unchanged on subsequent runs.

If the local tag was created but its push failed, inspect the remote before
retrying `git push origin refs/tags/TAG` with the chosen tag in place of `TAG`.
Keep the tag on the commit that was previewed.
