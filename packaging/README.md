# Debian Packages

Build binaries as described in the [development instructions](../README.md#development),
then package them from `build/binaries/`. For example, run these commands from
the repository root to build musl packages for amd64:

```sh
mise run build x86_64-unknown-linux-musl
mise run package:deb x86_64-unknown-linux-musl
```

Packages are written to `build/debs/`.

Both `rugix-ctrl-gnu` and `rugix-ctrl-musl` include two systemd services:

- `rugix-apps-restore-units.service` restores binary app units after a reboot.
- `rugix-apps-recover.service` recovers interrupted app transitions after boot.

Package installation enables both services, including when building an image
without a running systemd instance. On a running systemd system, installation
also starts them through Debian's service policy helper. Upgrades preserve
disabled and masked services and leave completed restoration and recovery
services running. Purging a package removes its service enablement state.

The packages install units in `/usr/lib/systemd/system/`. Local overrides in
`/etc/systemd/system/`, including units supplied by the standalone installer,
take precedence.

Run `python3 scripts/tests/test_build_debs.py` on a Debian or Ubuntu system to
test package contents and offline service enablement, upgrades, and purge.
The tests use temporary directories and require `dpkg-deb` and
`deb-systemd-helper`; they do not require root.
