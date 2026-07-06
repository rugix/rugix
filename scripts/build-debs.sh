#!/usr/bin/env bash
set -euo pipefail

# Build Debian packages from pre-built binaries in build/binaries/.
#
# Usage: ./scripts/build-debs.sh [TARGET...]
#
# If no targets are specified, packages are built for all targets found
# in build/binaries/. The output .deb files are placed in build/debs/.

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BINARIES_DIR="${PROJECT_DIR}/build/binaries"
OUTPUT_DIR="${PROJECT_DIR}/build/debs"

# Map Rust target triples to Debian architectures.
rust_target_to_deb_arch() {
    local target="$1"
    case "${target}" in
        x86_64-unknown-linux-*)  echo "amd64" ;;
        i686-unknown-linux-*)    echo "i386" ;;
        aarch64-unknown-linux-*) echo "arm64" ;;
        armv7-unknown-linux-*)   echo "armhf" ;;
        arm-unknown-linux-*hf)   echo "armhf" ;;
        arm-unknown-linux-*)     echo "armel" ;;
        riscv64gc-unknown-linux-*) echo "riscv64" ;;
        *)
            echo "error: unsupported target: ${target}" >&2
            return 1
            ;;
    esac
}

# Extract the libc variant (musl or gnu) from a Rust target triple.
rust_target_to_libc() {
    local target="$1"
    case "${target}" in
        *-musl*) echo "musl" ;;
        *-gnu*)  echo "gnu" ;;
        *)
            echo "error: cannot determine libc for target: ${target}" >&2
            return 1
            ;;
    esac
}

# Compute a Debian-compatible version from git describe output.
# v0.8.17         -> 0.8.17
# v0.8.17-30-g... -> 0.8.17+30.g...
compute_version() {
    local git_version
    git_version="$(git -C "${PROJECT_DIR}" describe --tags --always)"
    # Strip leading 'v'.
    git_version="${git_version#v}"
    # Replace the first '-' (commit count separator) with '+' and any
    # subsequent '-' with '.' to produce a valid Debian version.
    if [[ "${git_version}" == *-* ]]; then
        local base="${git_version%%-*}"
        local rest="${git_version#*-}"
        git_version="${base}+${rest//-/.}"
    fi
    echo "${git_version}"
}

# Descriptions keyed by binary name.
description_for() {
    case "$1" in
        rugix-ctrl)    echo "Rugix system management tool" ;;
        rugix-bundler) echo "Rugix bundle creation tool" ;;
        rugix-util)    echo "Rugix system utility" ;;
        rugix-bakery)  echo "Rugix image builder" ;;
        rugix-isolate) echo "Rugix isolation utility" ;;
        *)             echo "Rugix component" ;;
    esac
}

build_deb() {
    local binary_path="$1"
    local deb_arch="$2"
    local version="$3"
    local libc="$4"

    local binary_name
    binary_name="$(basename "${binary_path}")"

    # Package name includes the libc variant to distinguish musl from gnu
    # builds. Both install the same binary path, so they conflict.
    local package_name="${binary_name}-${libc}"

    # Build the Conflicts list excluding the package itself.
    local conflicts=""
    for variant in musl gnu; do
        if [ "${variant}" != "${libc}" ]; then
            conflicts="${binary_name}-${variant}"
        fi
    done

    local description
    description="$(description_for "${binary_name}") (${libc})"

    local staging_dir
    staging_dir="$(mktemp -d)"
    trap "rm -rf '${staging_dir}'" RETURN

    # Install the binary.
    install -Dm755 "${binary_path}" "${staging_dir}/usr/bin/${binary_name}"

    # Install the copyright file (required by Debian Policy 12.5).
    local doc_dir="${staging_dir}/usr/share/doc/${package_name}"
    mkdir -p "${doc_dir}"
    cat > "${doc_dir}/copyright" <<COPY
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: ${binary_name}
Upstream-Contact: Silitics GmbH <info@silitics.com>
Source: https://github.com/rugix/rugix/
Comment: This binary statically links third-party Rust crates. A full
 machine-readable Software Bill of Materials (SBOM) in CycloneDX format
 is available in the upstream release tarballs at
 https://github.com/rugix/rugix/releases

Files: *
Copyright: Silitics GmbH <info@silitics.com>
License: MIT or Apache-2.0

License: MIT
 On Debian systems, the full text of the MIT license
 can be found in /usr/share/common-licenses/MIT.

License: Apache-2.0
 On Debian systems, the full text of the Apache License Version 2.0
 can be found in /usr/share/common-licenses/Apache-2.0.
COPY

    # Compute installed size in KiB (as Debian expects).
    local installed_size
    installed_size="$(du -sk "${staging_dir}" | cut -f1)"

    # Write the control file.
    mkdir -p "${staging_dir}/DEBIAN"
    cat > "${staging_dir}/DEBIAN/control" <<EOF
Package: ${package_name}
Source: rugix-debian
Version: ${version}
Architecture: ${deb_arch}
Maintainer: Silitics GmbH <info@silitics.com>
Installed-Size: ${installed_size}
Conflicts: ${conflicts}
Priority: optional
Section: embedded
Description: ${description}
Homepage: https://rugix.org/
License: MIT or Apache-2.0
EOF

    # Build the .deb.
    local deb_file="${OUTPUT_DIR}/${package_name}_${version}_${deb_arch}.deb"
    dpkg-deb --build --root-owner-group "${staging_dir}" "${deb_file}"
    echo "Built ${deb_file}"
}

main() {
    local version
    version="$(compute_version)"
    echo "Version: ${version}"

    if [ ! -d "${BINARIES_DIR}" ]; then
        echo "error: ${BINARIES_DIR} does not exist, build binaries first" >&2
        exit 1
    fi

    mkdir -p "${OUTPUT_DIR}"

    # Determine which targets to process.
    local targets=()
    if [ $# -gt 0 ]; then
        targets=("$@")
    else
        for dir in "${BINARIES_DIR}"/*/; do
            [ -d "${dir}" ] || continue
            targets+=("$(basename "${dir}")")
        done
    fi

    if [ ${#targets[@]} -eq 0 ]; then
        echo "error: no targets found in ${BINARIES_DIR}" >&2
        exit 1
    fi

    for target in "${targets[@]}"; do
        local target_dir="${BINARIES_DIR}/${target}"
        if [ ! -d "${target_dir}" ]; then
            echo "error: target directory ${target_dir} does not exist" >&2
            exit 1
        fi

        local deb_arch libc
        deb_arch="$(rust_target_to_deb_arch "${target}")"
        libc="$(rust_target_to_libc "${target}")"
        echo "Processing ${target} -> ${deb_arch} (${libc})"

        for binary in "${target_dir}"/rugix-*; do
            [ -f "${binary}" ] || continue
            # Skip .d dependency files and SBOM files.
            [[ "${binary}" == *.d ]] && continue
            [[ "${binary}" == *.json ]] && continue
            build_deb "${binary}" "${deb_arch}" "${version}" "${libc}"
        done
    done
}

main "$@"
