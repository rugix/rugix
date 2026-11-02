# System Tests

The system tests check Rugix Ctrl and Rugix Bundler on real systems. Each test
bakes an operating system image with Rugix Bakery, boots it in a QEMU virtual
machine (VM), and exercises Rugix Ctrl over SSH, for example, by installing an
update bundle and rebooting into it. The tests use
[Rugix Testkit](https://github.com/rugix/rugix-testkit), which documents the
available fixtures. The Python dependency in `pyproject.toml` and the Bakery
repository in `rugix-bakery.toml` pin the same Testkit revision. Update both
when upgrading Testkit.

## Running the Tests

Prerequisites:

- A container runtime (Podman or Docker) for Rugix Bakery.
- `qemu-system-x86_64` with OVMF firmware, and `swtpm` for the TPM tests.
- `openssl`, which generates the update signing keys in `keys/`.
- Skopeo for packing Docker Compose apps and xdelta3 for static deltas.

The tests need builds of Rugix Ctrl and Rugix Bundler. The systems install
Rugix Ctrl from these builds and the tests run Rugix Bundler from them. From the
repository root, build them into `build/binaries`:

```sh
mise run build x86_64-unknown-linux-musl x86_64-unknown-linux-gnu
```

The `init-quiet` system needs the `x86_64-unknown-linux-gnu` build. Set
`RUGIX_BINARIES_DIR` to use builds from elsewhere and `RUGIX_BUNDLER` to select
a specific Bundler binary.

Rugix Bakery runs from the image named by `RUGIX_BAKERY_IMAGE`, which must be
available locally. From the repository root, run all tests on four parallel
workers:

```sh
export RUGIX_BAKERY_IMAGE=ghcr.io/rugix/rugix-bakery:branch-main
podman pull "$RUGIX_BAKERY_IMAGE"
mise run test:system -n 4
```

Any other pytest arguments work as well, for example, to run a single module:

```sh
mise run test:system test_update_bundle.py
```

Tests marked as `extended` only run when `RUGIX_TESTS_EXTENDED=1` is set. The
serial output and command history of each test's VMs end up in
`test-outputs/`.

Bakery does not notice when mounted binaries change. After rebuilding Rugix
Ctrl, delete `tests/.rugix/` so that cached layers pick up the new build. The
tests fail if a VM runs another Rugix Ctrl than the build under test.

Dynamic delta updates use block indexes to reuse blocks from existing slots,
downloading only missing blocks. The dynamic delta test compares downloads of
the same update before and after indexing the active slots. It requires at
least a 50% reduction and checks that the updated system boots. The comparison
allows filesystem metadata to change between baked images without assuming a
fixed number of changed blocks.

## Project Layout

This directory is a Rugix Bakery project. `rugix-bakery.toml` declares the test
systems, which build on layers in `layers/` and recipes in `recipes/`. Most
layers extend `customized-efi`, which itself builds on the testkit's
`rugix-testkit/debian-efi` base layer. `apps/` and `bundles/` contain the
sources of app bundles and update bundles that tests pack on the host.
