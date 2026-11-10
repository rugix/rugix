#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

target="${1:?Usage: build-mac.sh TARGET}"
RUGIX_GIT_VERSION="$(git describe --tags --always)"
export RUGIX_GIT_VERSION
cargo build --locked --release --target "$target" --bin rugix-bundler -F xz2/static
tar -cf "binaries-${target}.tar" -C "target/${target}/release" rugix-bundler
