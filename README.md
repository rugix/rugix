<p align="center">
    <img src="https://rugix.org/img/logo.svg" width="12%" alt="Rugix Logo">
</p>
<h1 align="center">
    Rugix
</h1>
<h4 align="center">
    Robust and Secure Over-the-Air Updates for Embedded Linux
</h4>
<p align="center">
  <a href="https://github.com/rugix/rugix/releases"><img alt="Rugix Version Badge" src="https://img.shields.io/github/v/tag/rugix/rugix?label=version"></a>
  <a href="https://github.com/rugix/rugix/actions"><img alt="Pipeline Status Badge" src="https://img.shields.io/github/actions/workflow/status/rugix/rugix/check-and-lint.yml"></a>
</p>

Rugix is an open-source tool suite for building robust, Linux-powered products. It consists of two tools:

- [**Rugix Ctrl**](https://github.com/rugix/rugix): On-device update engine. Deploy updates with confidence, never bricking a device.
- [**Rugix Bakery**](https://github.com/rugix/rugix-bakery): Custom Linux build system. Build OTA-ready images in days, not months.

Use both together for a complete solution, or integrate Rugix Ctrl into your existing Yocto or Buildroot workflow.

[**Get started today! Build your first system and deploy an update, all in under 30 minutes!**](https://rugix.org/docs/getting-started) 🚀

## Rugix Ctrl

This repository contains Rugix Ctrl, a state-of-the-art update and state management engine:

- **A/B Updates**: Atomic system updates with automatic rollback on failure.
- **Delta Updates**: [Highly-efficient delta updates](https://rugix.org/blog/efficient-delta-updates) minimizing bandwidth.
- **Signature Verification**: Cryptographic verification _before_ installing anything anywhere.
- **Compatibility Checks**: Verifies system and application updates are compatible before installation.
- **State Management**: Flexible state management inspired by container-based architectures.
- **Application Updates**: Atomic deployment and rollback of [application workloads](https://rugix.org/docs/ctrl/application-updates/).
- **Vendor-Agnostic**: Compatible with [various fleet management solutions](https://rugix.org/docs/ctrl/advanced/fleet-management) (avoids lock-in).
- **Flexible Boot Flows**: Supports [any bootloader and boot process](https://rugix.org/docs/ctrl/advanced/boot-flows).
- **Yocto Integration**: [Ready-made Yocto layers](https://github.com/rugix/meta-rugix) available.

Rugix Ctrl supports different update strategies (symmetric A/B, asymmetric with recovery, incremental updates) and can be adapted to almost any requirements you may have for robust and secure updates.

Works with Yocto, Buildroot, and other Linux build systems.

[For details, check out Rugix Ctrl's documentation.](https://rugix.org/docs/ctrl)

## Rugix Bakery

Robust over-the-air updates require system images built to support atomic updates. Traditional tools like Yocto are powerful but complex to set up and maintain, often taking teams months to build a production-ready pipeline. This complexity also creates risk: often only one person at a company truly understands the setup.

[**Rugix Bakery**](https://github.com/rugix/rugix-bakery) makes building OTA-ready system images (almost) **as easy as writing a Dockerfile**. Spend your time on what provides value to your users, not system-level details and build pipeline complexity.

[For details, check out the Rugix Bakery repository and documentation.](https://github.com/rugix/rugix-bakery)

## Why Rugix?

**Rugix is fully open-source**, including all features like delta updates. We integrate with different fleet management solutions and build systems, so **you stay in control without vendor lock-in**.

Rugix empowers teams to **ship robust products fast and without compromising on best practices** like read-only root filesystems, atomic OTA updates, reliable application deployment, and reproducible builds.

## Commercial Support

Rugix has been created and is maintained by [Silitics](https://silitics.com). Looking for commercial support? [We're here to help.](https://rugix.org/commercial-support) Need a fleet management solution? Check out [Nexigon](https://nexigon.cloud), by the creators of Rugix.

## ⚖️ Licensing

This project is licensed under either [MIT](https://github.com/rugix/rugix/blob/main/LICENSE-MIT) or [Apache 2.0](https://github.com/rugix/rugix/blob/main/LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache 2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

Made with ❤️ for OSS by [Silitics](https://www.silitics.com)
