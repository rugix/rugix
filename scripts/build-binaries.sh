#!/usr/bin/env bash
set -euo pipefail

# Build Rugix binaries for one or more Rust targets using Cross.
#
# Usage: ./scripts/build-binaries.sh TARGET [TARGET...]
#
# The binaries are placed in build/binaries/<target>/ and a tarball
# <target>.tar is created in build/binaries/.
#
# Cross and cargo-cyclonedx are provided by the repository's mise toolchain.

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_DIR}/build/binaries"

CROSS_BIN="${CROSS_BIN:-$(command -v cross || true)}"
CARGO_CYCLONEDX_BIN="${CARGO_CYCLONEDX_BIN:-$(command -v cargo-cyclonedx || true)}"

require_tool() {
    local name="$1"
    local path="$2"
    if [ -z "${path}" ]; then
        echo "error: ${name} is not available; run 'mise install' first" >&2
        exit 1
    fi
}

build_target() {
    local target="$1"

    echo "==> Building ${target}"

    local git_version
    git_version="$(git -C "${PROJECT_DIR}" describe --tags --always)"
    export RUGIX_GIT_VERSION="${git_version}"

    # Cross must be run from the project directory — it maps the working
    # directory into the Docker container rather than using --manifest-path.
    (cd "${PROJECT_DIR}" && "${CROSS_BIN}" build --locked --release --target "${target}")

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

    require_tool cross "${CROSS_BIN}"
    require_tool cargo-cyclonedx "${CARGO_CYCLONEDX_BIN}"
    mkdir -p "${OUTPUT_DIR}"

    for target in "$@"; do
        build_target "${target}"
    done
}

main "$@"
