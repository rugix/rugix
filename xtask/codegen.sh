#!/usr/bin/env bash

set -euo pipefail

pushd crates/apps/rugix-ctrl
sidex generate rust src/config/generated
./generate-json-schema.sh
popd

pushd crates/libs/rugix-bundle
sidex generate rust src/manifest/generated
./generate-json-schema.sh
popd

cargo +nightly fmt