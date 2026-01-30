<p align="center">
    <img src="https://rugix.org/img/logo.svg" width="12%" alt="Rugix Logo">
</p>
<h1 align="center">
    Rugix
</h1>
<h4 align="center">
    The open-source tool suite to build <em>secure</em> and <em>reliable</em> embedded Linux<br> devices with <em>efficient and secure</em> over-the-air update capabilities.
</h4>
<p align="center">
  <a href="https://github.com/rugix/rugix/releases"><img alt="Rugix Version Badge" src="https://img.shields.io/github/v/tag/rugix/rugix?label=version"></a>
  <a href="https://github.com/rugix/rugix/actions"><img alt="Pipeline Status Badge" src="https://img.shields.io/github/actions/workflow/status/rugix/rugix/check-and-lint.yml"></a>
</p>

💡 **TL;DR**: Rugix is a suite of open-source tools to **build and deploy reliable embedded Linux devices at scale with efficient and secure over-the-air (OTA) update capabilities**.
The tool suite consists of two powerful and modular tools:

- **Rugix Ctrl**: On-device tool for installing over-the-air updates and managing state.
- **Rugix Bakery**: Flexible, user-friendly build system for bespoke Linux distributions.

While these tools are designed two work seamlessly together, **they can be used independently**.
By providing a unified and efficient modern development workflow, **Rugix enables better results at a lower cost**.
If you prefer [Yocto](https://www.yoctoproject.org) over Rugix Bakery, we also provide open-source [Yocto layers for Rugix](https://github.com/silitics/meta-rugix/).

[**Get started today! Build your first system and deploy an update, all in under 30 minutes!**](https://rugix.org/docs/getting-started) 🚀

## Rugix Ctrl: The Update Mechanism

Rugix Ctrl has all features you would expect from a state-of-the-art update solution and more:

- **Atomic A/B system updates** with popular bootloaders out of the box.
- **Streaming updates** as well as [**best-in-class delta updates**](https://rugix.org/blog/efficient-delta-updates) out of the box.
- Builtin **cryptographic signature verification** _before_ installing anything anywhere.
- Supports **any update scenario**, including **non-A/B updates and incremental updates**.
- Supports **any bootloader and boot process** through [custom _boot flows_](https://rugix.org/docs/ctrl/advanced/boot-flows).
- **Robust state management mechanism** inspired by container-based architectures.
- Integrates well with [different fleet management solutions](https://rugix.org/docs/ctrl/advanced/fleet-management) (avoids vendor lock-in).
- Provides powerful interfaces to built your own update workflow upon.
- Open-source [Yocto layers](https://github.com/silitics/meta-rugix/) for seamless Rugix integration.

Rugix Ctrl **supports or can be adapted to almost any requirements you may have** when it comes to robust and secure updates of your entire system as well as its individual components.

[For details, check out Rugix Ctrl's documentation.](https://rugix.org/docs/ctrl)

## Rugix Bakery: The Development Tool

You wrote your application and now need to integrate it into a full system ready to be flashed onto your device or deployed as an update?
Rugix Bakery makes this process (almost) **as easy as writing a Dockerfile, enabling you to focus on what provides value to your users** instead of system-level details.

- Build upon proven distributions such as **Debian and Alpine Linux**.
- **Over-the-air update capabilities** powered by Rugix Ctrl out of the box.
- Build everything **from source to image in a container-based environment**.
- Define **multiple system variants**, including variants for testing.
- Builtin **system testing framework** and **support for running VMs**.

With Rugix Bakery, you get a **comprehensive tool to build, test, and run your system** similar to what you will find with modern software development tooling, like [Cargo](https://doc.rust-lang.org/cargo/) (Rust) or [uv](https://docs.astral.sh/uv/) (Python).

[For details, check out Rugix Bakery's documentation.](https://rugix.org/docs/bakery)

## Why Rugix?

While there are already plenty of tools for building images, updating systems, and managing state in the embedded Linux ecosystem, integrating them into a robust, coherent solution remains a significant challenge.
With Rugix, we aim to **simplify the development of embedded Linux devices by providing a unified, modern suite of tools that seamlessly integrate** to provide an efficient workflow for building, updating, and managing embedded Linux systems at scale.
We believe that **building embedded Linux devices should not be as complicated as it often is today**.

While simplicity is our first key tenet, our second is to **provide solutions that are absolutely robust**.
Embedded devices must stay operational no matter what, always, anywhere.
With Rugix, we **make it easy to follow best practices** for building reliable devices, like read-only system partitions, fully atomic updates with on-device validation, and declarative, ideally fully reproducible builds.

## ⚖️ Licensing

This project is licensed under either [MIT](https://github.com/rugix/rugix/blob/main/LICENSE-MIT) or [Apache 2.0](https://github.com/rugix/rugix/blob/main/LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache 2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

Made with ❤️ for OSS by [Silitics](https://www.silitics.com)
