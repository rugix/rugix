#!/usr/bin/env bash
set -euo pipefail

# Build a metadata-only Debian source package for Rugix.
#
# Usage: ./scripts/build-source-package.sh
#
# The source package exists to satisfy archives and image builders
# (e.g. ELBE) that require a source package alongside every binary
# .deb. It is not buildable; the shipped binaries are cross-compiled
# by scripts/build-binaries.sh and packaged by scripts/build-debs.sh.
#
# Outputs <source>_<version>.dsc and <source>_<version>.tar.xz to
# build/source/.

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_DIR="${PROJECT_DIR}/packaging/debian"
OUTPUT_DIR="${PROJECT_DIR}/build/source"
SOURCE_NAME="rugix-debian"
MAINTAINER="Silitics GmbH <info@silitics.com>"

source "${PROJECT_DIR}/scripts/debian-version.sh"

main() {
    if [ ! -d "${TEMPLATE_DIR}" ]; then
        echo "error: ${TEMPLATE_DIR} does not exist" >&2
        exit 1
    fi

    local version commit date
    version="$(rugix_debian_version)"
    commit="$(git -C "${PROJECT_DIR}" rev-parse HEAD)"
    date="$(git -C "${PROJECT_DIR}" show -s --format=%aD HEAD)"

    echo "Source:  ${SOURCE_NAME}"
    echo "Version: ${version}"
    echo "Commit:  ${commit}"

    local staging_root staging_dir
    staging_root="$(mktemp -d)"
    trap "rm -rf '${staging_root}'" EXIT
    staging_dir="${staging_root}/${SOURCE_NAME}-${version}"
    mkdir -p "${staging_dir}"

    # Minimal payload: the resolved Rust dependency graph, the exact
    # upstream commit, license files, and a top-level README.
    cp "${PROJECT_DIR}/Cargo.lock"     "${staging_dir}/Cargo.lock"
    cp "${PROJECT_DIR}/LICENSE-MIT"    "${staging_dir}/LICENSE-MIT"
    cp "${PROJECT_DIR}/LICENSE-APACHE" "${staging_dir}/LICENSE-APACHE"
    cp "${PROJECT_DIR}/README.md"      "${staging_dir}/README.md"
    echo "${commit}" > "${staging_dir}/GIT_COMMIT"

    # Copy the static debian/ template, then generate the changelog.
    cp -r "${TEMPLATE_DIR}" "${staging_dir}/debian"
    cat > "${staging_dir}/debian/changelog" <<CHG
${SOURCE_NAME} (${version}) unstable; urgency=medium

  * Metadata-only source package for upstream commit ${commit}.

 -- ${MAINTAINER}  ${date}
CHG

    mkdir -p "${OUTPUT_DIR}"

    # dpkg-source writes its output one directory above the source
    # tree, so build inside staging_root and then collect the results.
    (cd "${staging_root}" && dpkg-source --build "${SOURCE_NAME}-${version}")
    mv "${staging_root}/${SOURCE_NAME}_${version}".* "${OUTPUT_DIR}/"

    echo "Built source package:"
    ls -1 "${OUTPUT_DIR}/${SOURCE_NAME}_${version}".*
}

main "$@"
