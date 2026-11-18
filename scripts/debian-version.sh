#!/usr/bin/env bash
# Shared by binary and source packaging so their Debian versions always agree.

rugix_debian_version() {
    local version distance=""
    version="${RUGIX_GIT_VERSION:-$(git -C "${PROJECT_DIR}" describe --tags --always)}"
    if [[ "${version}" =~ ^(.*)-([0-9]+)-g([0-9a-f]+)$ ]]; then
        version="${BASH_REMATCH[1]}"
        distance="+${BASH_REMATCH[2]}.g${BASH_REMATCH[3]}"
    fi
    version="${version#v}"
    # Debian's tilde sorts prereleases before the corresponding stable version.
    version="${version/-/\~}"
    echo "${version}${distance}"
}
