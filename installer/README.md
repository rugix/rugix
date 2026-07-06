# Rugix Installers

This directory contains standalone installer scripts for integrating Rugix
components into existing Linux systems.

The installers must be run as root. Open an interactive root shell first, for
example with `sudo -i` or `su -`, and then run the commands below. The `#`
prompt in the examples indicates that the command is run as root.

## Rugix Apps

`install-rugix-apps.sh` installs:

- Docker, if it is not already available.
- `rugix-ctrl` from a Rugix GitHub release Debian package.
- Systemd units required by Rugix Apps:
  - `rugix-apps-restore-units.service`
  - `rugix-apps-recover.service`

Run it as root on an apt-based system with systemd, such as Debian or Ubuntu:

```sh
# bash installer/install-rugix-apps.sh
```

By default, `RUGIX_VERSION=v1` resolves to the latest stable `v1.x` release
from `rugix/rugix`. `latest` and `vN` selectors ignore prereleases. Pass an
exact tag or set `RUGIX_VERSION` to install that tag, including prerelease tags:

```sh
# bash installer/install-rugix-apps.sh v1.2.0
# RUGIX_VERSION=latest bash installer/install-rugix-apps.sh
# RUGIX_VERSION=v1.2.0 bash installer/install-rugix-apps.sh
# RUGIX_GITHUB_REPO=my-org/rugix RUGIX_VERSION=v1.2.0 bash installer/install-rugix-apps.sh
```

When installing directly from GitHub, pass the version to `bash`, not to
`curl`:

```sh
# curl -fsSL https://raw.githubusercontent.com/rugix/rugix/refs/heads/main/installer/install-rugix-apps.sh | bash
# curl -fsSL https://raw.githubusercontent.com/rugix/rugix/refs/heads/main/installer/install-rugix-apps.sh | bash -s -- v1.2.1-dev.2
```

Do not put `RUGIX_VERSION=...` before `curl` in a pipeline; that only sets the
variable for the `curl` process.

The installer uses the `rugix-ctrl-musl` Debian package by default. Set
`RUGIX_DEB_VARIANT=gnu` to install `rugix-ctrl-gnu` instead. The Rugix Ctrl
package only provides the `rugix-ctrl` binary; the app recovery systemd units
are installed by this script.
