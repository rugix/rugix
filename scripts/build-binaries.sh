#!/usr/bin/env bash
set -euo pipefail

# Build Rugix binaries for one or more Rust targets using Cross.
#
# Usage: ./scripts/build-binaries.sh TARGET [TARGET...]
#
# The binaries are placed in build/binaries/<target>/ and a tarball
# <target>.tar is created in build/binaries/.
#
# Cross is downloaded automatically if not already cached in build/cross/.

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_DIR}/build/binaries"

CROSS_VERSION="0.2.5"
CARGO_CYCLONEDX_VERSION="0.5.7"
TOOLS_DIR="${PROJECT_DIR}/build/tools"
CROSS_BIN="${TOOLS_DIR}/cross-${CROSS_VERSION}"
CARGO_CYCLONEDX_BIN="${TOOLS_DIR}/cargo-cyclonedx-${CARGO_CYCLONEDX_VERSION}"

# Download Cross if not already cached.
ensure_cross() {
    if [ -x "${CROSS_BIN}" ]; then
        return
    fi
    echo "==> Downloading Cross ${CROSS_VERSION}"
    mkdir -p "${TOOLS_DIR}"
    local url="https://github.com/cross-rs/cross/releases/download/v${CROSS_VERSION}/cross-x86_64-unknown-linux-musl.tar.gz"
    curl -fsSL "${url}" | tar -xz -C "${TOOLS_DIR}"
    mv "${TOOLS_DIR}/cross" "${CROSS_BIN}"
    echo "==> Cross ${CROSS_VERSION} installed to ${CROSS_BIN}"
}

# Download cargo-cyclonedx if not already cached.
ensure_cargo_cyclonedx() {
    if [ -x "${CARGO_CYCLONEDX_BIN}" ]; then
        return
    fi
    echo "==> Downloading cargo-cyclonedx ${CARGO_CYCLONEDX_VERSION}"
    mkdir -p "${TOOLS_DIR}"
    local url="https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-${CARGO_CYCLONEDX_VERSION}/cargo-cyclonedx-x86_64-unknown-linux-musl.tar.xz"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    curl -fsSL "${url}" | tar -xJ -C "${tmp_dir}"
    mv "${tmp_dir}"/cargo-cyclonedx-x86_64-unknown-linux-musl/cargo-cyclonedx "${CARGO_CYCLONEDX_BIN}"
    rm -rf "${tmp_dir}"
    echo "==> cargo-cyclonedx ${CARGO_CYCLONEDX_VERSION} installed to ${CARGO_CYCLONEDX_BIN}"
}

build_target() {
    local target="$1"

    echo "==> Building ${target}"

    local git_version
    git_version="$(git -C "${PROJECT_DIR}" describe --tags --always)"
    export RUGIX_GIT_VERSION="${git_version}"

    # Cross must be run from the project directory — it maps the working
    # directory into the Docker container rather than using --manifest-path.
    (cd "${PROJECT_DIR}" && "${CROSS_BIN}" build --frozen --release --target "${target}")

    # Determine the target directory (respect CARGO_TARGET_DIR).
    local target_dir="${CARGO_TARGET_DIR:-${PROJECT_DIR}/target}"
    local release_dir="${target_dir}/${target}/release"

    # Generate SBOMs.
    echo "==> Generating SBOMs for ${target}"
    (cd "${PROJECT_DIR}" && "${CARGO_CYCLONEDX_BIN}" cyclonedx -f json --target "${target}")

    # Collect binaries and SBOMs into build/binaries/<target>/.
    local binaries_dir="${OUTPUT_DIR}/${target}"
    rm -rf "${binaries_dir}"
    mkdir -p "${binaries_dir}"

    for binary in "${release_dir}"/rugix-*; do
        [ -f "${binary}" ] || continue
        # Skip .d dependency files.
        [[ "${binary}" == *.d ]] && continue
        local name
        name="$(basename "${binary}")"
        cp "${binary}" "${binaries_dir}/"
        # Copy the corresponding SBOM if it exists.
        local sbom="${PROJECT_DIR}/crates/apps/${name}/${name}.cdx.json"
        if [ -f "${sbom}" ]; then
            cp "${sbom}" "${binaries_dir}/${name}.cdx.json"
        fi
    done

    # Create a tarball alongside the target directory.
    tar -cf "${OUTPUT_DIR}/binaries-${target}.tar" -C "${binaries_dir}" .

    echo "==> Built ${target} -> ${binaries_dir}"
}

main() {
    if [ $# -eq 0 ]; then
        echo "Usage: $0 TARGET [TARGET...]" >&2
        exit 1
    fi

    ensure_cross
    ensure_cargo_cyclonedx
    mkdir -p "${OUTPUT_DIR}"

    for target in "$@"; do
        build_target "${target}"
    done
}

main "$@"
