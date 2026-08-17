<p align="center">
    <img src="https://rugix.org/img/logo.svg" width="12%" alt="Rugix Logo">
</p>
<h1 align="center">
    Rugix
</h1>
<h4 align="center">
    The Open-Source Toolkit for Embedded Linux
</h4>
<p align="center">
  <a href="https://github.com/rugix/rugix/releases"><img alt="Rugix Version Badge" src="https://img.shields.io/github/v/tag/rugix/rugix?label=version"></a>
  <a href="https://github.com/rugix/rugix/actions"><img alt="Pipeline Status Badge" src="https://img.shields.io/github/actions/workflow/status/rugix/rugix/check-and-lint.yml"></a>
</p>

> [!NOTE]
> **Support:** This repository is covered by [Tier 1: Core](https://rugix.org/support-commitment/#tier-core) of the Rugix Support Commitment.

Rugix is an open-source toolkit for building and maintaining robust Linux-powered
products from development to production. Its tools support on-device lifecycle
management, custom image builds, and browser-based operation of individual
devices:

- [**Rugix Ctrl**](https://github.com/rugix/rugix): On-device tool for robust system and application updates and persistent state management.
- [**Rugix Bakery**](https://github.com/rugix/rugix-bakery): Build system for custom, OTA-ready Linux system images.
- [**Rugix Admin**](https://github.com/rugix/rugix-admin): Lightweight, browser-based interface for operating individual Rugix devices.

Rugix Bakery builds system images with Rugix Ctrl update support out of the box.
Rugix Ctrl integrates into existing Yocto, Buildroot, and other Linux build
workflows. Rugix Admin provides local access for developers and operators.

[**Get started today! Build your first system and deploy an update, all in under 30 minutes!**](https://rugix.org/docs/getting-started) 🚀

## Rugix Ctrl

This repository contains Rugix Ctrl, which provides reliable on-device management
for Linux devices:

- **Fail-Safe System Updates**: Atomic A/B updates with automatic rollback on failure.
- **Delta Updates**: [Highly-efficient delta updates](https://rugix.org/blog/efficient-delta-updates) minimizing bandwidth.
- **Signature Verification**: Cryptographic verification _before_ installing anything anywhere.
- **Compatibility Checks**: Verifies system and application updates are compatible before installation.
- **State Management**: Flexible state management inspired by container-based architectures.
- **Application Updates**: Atomic deployment and rollback of [application workloads](https://rugix.org/docs/ctrl/application-management/).
- **Vendor-Agnostic**: Compatible with [various fleet management solutions](https://rugix.org/docs/ctrl/integration/fleet-management/) (avoids lock-in).
- **Flexible Boot Flows**: Supports [any bootloader and boot process](https://rugix.org/docs/ctrl/updates/system-updates/boot-flows/).
- **Yocto Integration**: [Ready-made Yocto layers](https://github.com/rugix/meta-rugix) available.

Rugix Ctrl supports different update strategies (symmetric A/B, asymmetric with recovery, incremental updates) and can be adapted to almost any requirements you may have for robust and secure updates.

Works with Yocto, Buildroot, and other Linux build systems.

[For details, check out Rugix Ctrl's documentation.](https://rugix.org/docs/ctrl)

For the precise update durability boundaries, interruption behavior, and operator recovery
expectations implemented by this repository, see [Update Reliability and Recovery](docs/update-reliability.md).

## Rugix Admin

[**Rugix Admin**](https://github.com/rugix/rugix-admin) complements Rugix Ctrl with a
lightweight, browser-based management interface for individual devices. Developers
and operators can inspect system status, install system and application updates,
manage application workloads, and review operation logs directly on a device. It is
well suited for development, demos, and field service.

## Rugix Bakery

Robust over-the-air updates require system images built to support atomic updates. Traditional tools like Yocto are powerful but complex to set up and maintain, often taking teams months to build a production-ready pipeline. This complexity also creates risk: often only one person at a company truly understands the setup.

[**Rugix Bakery**](https://github.com/rugix/rugix-bakery) makes building OTA-ready system images (almost) **as easy as writing a Dockerfile**. Spend your time on what provides value to your users, not system-level details and build pipeline complexity.

[For details, check out the Rugix Bakery repository and documentation.](https://github.com/rugix/rugix-bakery)

## Why Rugix?

**Rugix is fully open-source and permissively licensed**, including features such as
delta updates. Rugix's tools integrate with different build systems and fleet
management solutions, so **you stay in control without vendor lock-in**.

Rugix empowers teams to **ship robust products fast and without compromising on best practices** like read-only root filesystems, atomic OTA updates, reliable application deployment, and reproducible builds.


## Development

Rugix uses [mise](https://mise.jdx.dev/) for development tools and tasks. Tool
specifications stay intentionally loose where mise can resolve them; `mise.lock` records
the exact versions and checksums used by developers and CI. Rust is managed separately
by rustup through `rust-toolchain.toml`, so Cargo, rust-analyzer, and editors use the same
dated nightly without requiring mise activation.

Install the locked toolchain and inspect the available commands:

```bash
mise install
mise tasks
```

Common workflows are:

```bash
mise run check                         # formatting, Clippy, dependency policy/advisories, and unit tests
mise run fmt
mise run codegen
mise run build x86_64-unknown-linux-musl
mise run package:deb x86_64-unknown-linux-musl
mise run test:system
```

Run `mise run doctor` to check host dependencies. Development requires rustup; entering
the repository or running Cargo installs the configured Rust toolchain as needed. Native
builds also require a C compiler, `pkg-config`, OpenSSL, and liblzma development files.
Cross-builds require Docker or Podman. The system tests additionally require QEMU and
OVMF.

To deliberately update the non-Rust toolchain, update the loose specifications if needed
and run `mise lock`; commit `mise.toml` and `mise.lock` together. Update Rust by changing
the dated channel in `rust-toolchain.toml`.

## Run Directly from Git with Nix

The Nix flake exposes each Rugix command as both a package and an app, so no checkout is
required:

```bash
nix run github:rugix/rugix#rugix-ctrl -- --help
nix run github:rugix/rugix#rugix-bundler -- --help
nix run github:rugix/rugix#rugix-util -- --help
```

Replace the flake reference with a tag or commit when a specific revision is required,
for example `github:rugix/rugix/v0.8.17#rugix-ctrl`.

## Commercial Support

Rugix has been created and is maintained by [Silitics](https://silitics.com). Looking for commercial support? [We're here to help.](https://rugix.org/commercial-support) Need a fleet management solution? Check out [Nexigon](https://nexigon.cloud), by the creators of Rugix.

## Licensing

This project is licensed under either [MIT](https://github.com/rugix/rugix/blob/main/LICENSE-MIT) or [Apache 2.0](https://github.com/rugix/rugix/blob/main/LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache 2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

Made with ❤️ for OSS by [Silitics](https://www.silitics.com)
