# Changelog

## Unreleased

Behavior Changes:

- Rugix Admin now has its own repository, installer, and release artifacts. It is no longer built or distributed from the Rugix Ctrl repository.
- Data partition mount failures now fall back to ephemeral state by default. Set `data-partition.fail-on-mount-error = true` when booting without persistent data must fail.

Security and Reliability:

- Harden bundle parsing with strict framing, bounded reads, compressed-block metadata validation, and error propagation for malformed or truncated input.
- Accept bundle signatures from any configured certificate root, broaden CMS signature interoperability, and continue checking other signatures and roots when one candidate is invalid.
- Confine bundle, application, and persistent-state paths; validate application archives before extraction; and reject unsafe names, traversal paths, and symlinked application-file destinations.
- Write bundles atomically, preserve update state across synchronization failures, synchronize payloads before completion, and retain deferred reboot targets.
- Make multi-application activation transactional, recover interrupted application updates, and report rolled-back or failed activations as failures.
- Validate generic, Mender, RAUC, and systemd boot-flow state mappings and preserve GPT and partition metadata when modifying disks.
- Replace remaining panic paths in bundle decoding, update installation, simulation, boot-flow handling, and application service management with reported errors.

Rugix Ctrl:

- Add an internal Unix-socket daemon mode that lets unprivileged Rugix Ctrl clients execute typed status, installation, system, and application operations through a privileged process. Destructive system and application lifecycle operation families require explicit daemon feature flags, and `rugix-ctrl daemon info` reports the daemon's effective policy.
- Detect the active boot group through transitive backing devices for device-mapper system roots.
- Log Rugix init errors that were previously ignored or only printed to stderr.
- Add opt-in `rugix.init.shell_on_error[=<seconds>]` kernel cmdline option for opening a debug shell after init errors. This is intentionally disabled by default to avoid exposing a root shell to someone with console access.
- Add `overlay-fallback: in-memory` state configuration to retry root overlay setup with an in-memory overlay when the configured overlay fails.
- Add boot flow capability reporting for userspace failure recovery and fall back to starting the underlying init on committed systems when Rugix init fails and the boot flow cannot recover userspace failures.
- Write Docker Compose activation diagnostics, including service status and recent logs, when bringing up a Rugix App generation fails.
- Add experimental component compatibility metadata discovery and `rugix-ctrl components` inspection commands for checking installed system, local, runtime, app, and synthetic host components.
- Check component compatibility before installing system updates, installing apps, or removing apps. Pass `--skip-compatibility-check` to bypass these checks.

Rugix Bundler:

- Rework Docker Compose image bundling to copy images with Skopeo, infer Compose `build:` entries, default local builds to Podman, and rewrite packaged Compose files to Rugix-owned bundle-local image tags. `--disable-pinning` now keeps the original Compose image references while still bundling the images.
- Allow update bundles to carry declared component metadata for compatibility checks.

Libraries:

- Add `rugix-component-set` for evaluating component capabilities, requirements, and conflicts, and use the published `anyver`, `byte-calc`, and `reportify` crates.
- Refresh dependencies to resolve the `crossbeam-epoch` security advisory.

## Version 1.2.0

Behavior changes:

- Bundle installation now rejects bundles without a block index by default. Pass `--insecure-allow-missing-block-index` to install such bundles.

Rugix Ctrl:

- Add data partition drivers.
- Support for optional slots.
- Override active boot group detection via `rugix.boot_group=<name>` on the kernel cmdline.
- Add `reboot` operation to boot flow interface.
- Allow the bootstrap marker to be placed in `rugix` instead of `.rugix`.
- Resolve parents of virtual block devices.
- Acquire a write guard on the config partition for file slots that live there.
- Gracefully handle boot flow errors during init.
- Fix infinite loop when scanning for the parent of a block device.

Rugix Bundler:

- Annotate opaque types in the published bundle manifest JSON Schemas with their JSON representation.
- Honor `--disable-pinning` when saving container images.
- Leave locally-built container images unpinned instead of failing.

## Version 1.1.2

- Fix PARTUUID issue when using an initramfs and the `tryboot` mechanism.

## Version 1.1.1

- Allow Rugix App bundles to be installed via HTTP.

## Version 1.1.0

- Introduction of Rugix Apps to manage application workloads.
- Prevent concurrent updates using a lock file.
- Support for systemd-boot.
- Fix panic when extracting payload file.

## Version 1.0.0

- Remove functionality for installing images.
- Make signatures mandatory unless opted out.
- Consolidate split of Rugix Ctrl and Rugix Bakery.

## Version 0.8.17

- Re-release of v0.8.16 due to immutable release preventing CI from publishing assets.

## Version 0.8.16

- Use `/usr/bin/env` instead of hard-coded paths.
- Improved progress reporting for delta updates.

**Note:** This release migrates to the Rugix GitHub organization.

## Version 0.8.15

- Parallel compression of Rugix update bundles.
- Project templates now default to Debian Trixie.

## Version 0.8.14

- Cryptographic integrity verification through embedded signatures.
- Compatibility with Mender and RAUC.
- State resets with backups of the old state.
- Data partition mount scripts.

## Version 0.8.13

- Fix build issues caused by layout changes in Raspberry Pi's firmware repository.

## Version 0.8.12

- Static delta updates using Xdelta.
- Update simulator as part of Rugix Bundler.

## Version 0.8.11

- Fix `fsck` invocation on data partition.

## Version 0.8.10

- Automated, built-in generation of SPDX SBOMs through Syft.

## Version 0.8.7

- Fix issue determining block device size on 32-bit platforms.

## Version 0.8.6

New features:

- Support GPT-based partition layouts on Raspberry Pi.

Bug fixes:

- Fix spurious boot errors after `fsck` repaired the data partition.
- Fix incompatibility issues with Raspberry Pi OS's initial ramdisk.

## Version 0.8.5

New features:

- Allow `auto_initramfs=1` on Raspberry Pi (required for SquashFS).
- Add new `update-install/progress` hook to report installation progress.

Bug fixes:

- Allow the default image path to be passed to `bake image`.
- Resolve compatibility issues when updating from older Rugix (Rugpi) versions.

## Version 0.8.4

- Fix broken reading of `system-build-info.json` on builds with a hot cache.

## Version 0.8.3

New features:

- Write release information to `/etc/rugix/system-build-info.json`.
- Support for SquashFS root filesystems (#6).

Bug fixes:

- Persist `machine-id` from state after updating rootfs.
- Check whether stdout is piped instead of stderr (#51).
- Change slot db directory to `/var/lib/rugix` (was `/var/rugix` before).
- Only copy image when output path differs from system image path (#53).

## Version 0.8.2

- Prevent error during update installation when using multiple block indices.

## Version 0.8.1

- Fix caching issue where cache is always cleared regardless of whether Docker image changed.

## Version 0.8.0

Rename to Rugix.

Rugix Ctrl:

- New format for update bundles.
- Adaptive delta updates with HTTP range queries.
- Support for any update scenario, including non-A/B updates and incremental updates.
- Support for any bootloader and boot process through custom boot flows.
- New JSON-based system information format.

Rugix Bakery:

- Ability to run VMs.
- Integrated system testing framework.

## Version 0.7.5

- Fixes off-by-one error in partition table sanity check affecting GPT layouts.

## Version 0.7.4

- Add support for verifying the hash of updates via `--check-hash`.

## Version 0.7.3

- Fixes issues with incompatible partition layouts when upgrading from v0.6 (see #29).

**Additional Notes:** Flashing a device with a v0.7.3 image and then installing an update based on an older 0.7 version will fail for the `rpi-` targets.

## Version 0.7.2

- Fixes bootstrapping of foreign architectures with `binfmt_misc`.

## Version 0.7.1

- Add `unknown` target.
- Limit size of MBR partitions (fix).

## Version 0.7.0

New features:

- Official support for Alpine Linux and Debian.
- Support for EFI systems and integration with Grub.
- Configurable image layouts.

Breaking changes to the image building pipeline:

- The `boot_flow` option has been superseded by `target`.
- The `include_firmware` option has been removed. To include a firmware update for Raspberry Pi, use the `core/rpi-include-firmware` recipe.
- The following recipes have been renamed:
  - `core/raspberrypi` => `core/rpi-raspios-setup`
  - `core/pi-cleanup` => `core/rpi-raspios-cleanup`
  - `core/apt-cleanup` => `core/pkg-cleanup` (also supports `apk` now)
  - `core/apt-update` => `core/pkg-cleanup` (also supports `apk` now)
  - `core/apt-upgrade` => `core/pkg-upgrade` (also supports `apk` now)
- The following recipes have been removed:
  - `core/disable-swap` (now part of `rpi-raspios-cleanup` via parameter)

## Version 0.6.6

- Allow for deferred reboots into the spare partition set.
- Make streaming updates the default.

## Version 0.6.5

- Allow booting from external USB devices.
- Fix issues with Docker due to the usage of `chroot`.

## Version 0.6.4

- Allow `gz` compressed tarballs as base layer.
- Check root filesystem size when building an image.
- Ignore any files in the `layers` directory not ending with `.toml`.

## Version 0.6.3

- Allow local `.tar` files to be used as a layer.
- Patch `/etc/fstab` instead of overwriting it.

## Version 0.6.2

- Create directories when baking images.
- Ignore `.DS_Store` directories/files.

## Version 0.6.1

- Transparent decompression of XZ-compressed images.
- Switch to streaming updates in Rugpi Admin.

## Version 0.6.0

- Introduction of layers.
- Introduction of repositories.
- Backwards-incompatible changes to image building pipeline:
  - Layers instead of recipes in `rugpi-bakery.toml`.
  - Removal of default recipes. Recipes must be explicitly enabled.
  - Separate `images` sections in `rugpi-bakery.toml`.

## Version 0.5.0

- Support for all models of Raspberry Pi via U-Boot.
- Support for persisting the overlay by default.
- Experimental support for streaming updates.

## Pre-Releases (0.1 to 0.4)

- Initial experimental version.
