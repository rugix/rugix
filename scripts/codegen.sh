#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

(
cd crates/apps/rugix-ctrl
mkdir -p generated
rm -rf generated/*
sidex generate json-schema generated/

# Copy generated JSON schemas to the schemas directory (repo root)
mkdir -p ../../../schemas
cp generated/rugix_ctrl.bootstrapping.BootstrappingConfig.schema.json ../../../schemas/rugix-ctrl-bootstrapping.schema.json
cp generated/rugix_ctrl.state.StateConfig.schema.json ../../../schemas/rugix-ctrl-state.schema.json
cp generated/rugix_ctrl.system.SystemConfig.schema.json ../../../schemas/rugix-ctrl-system.schema.json
cp generated/rugix_ctrl.config.Config.schema.json ../../../schemas/rugix-ctrl-config.schema.json
cp generated/rugix_ctrl.daemon.DaemonConfig.schema.json ../../../schemas/rugix-ctrl-daemon.schema.json
cp generated/rugix_ctrl.component.ComponentDeclaration.schema.json ../../../schemas/rugix-ctrl-component.schema.json
cp generated/rugix_ctrl.output.SystemInfoOutput.schema.json ../../../schemas/rugix-ctrl-output-info.schema.json
cp generated/rugix_ctrl.output.ComponentsOutput.schema.json ../../../schemas/rugix-ctrl-output-components.schema.json
cp generated/rugix_ctrl.output.ComponentsCheckOutput.schema.json ../../../schemas/rugix-ctrl-output-components-check.schema.json
cp generated/rugix_ctrl.output.AppListEntryOutput.schema.json ../../../schemas/rugix-ctrl-output-app-list-entry.schema.json
cp generated/rugix_ctrl.output.AppInfoOutput.schema.json ../../../schemas/rugix-ctrl-output-app-info.schema.json
cp generated/rugix_ctrl.output.AppGcAppOutput.schema.json ../../../schemas/rugix-ctrl-output-app-gc.schema.json
cp generated/rugix_ctrl.output.AppConfigurationSetOutput.schema.json ../../../schemas/rugix-ctrl-output-app-configuration-set.schema.json
cp generated/rugix_ctrl.output.AppFileOutput.schema.json ../../../schemas/rugix-ctrl-output-app-file.schema.json
cp generated/rugix_ctrl.output.StoreInfoOutput.schema.json ../../../schemas/rugix-ctrl-output-store-info.schema.json
cp generated/rugix_ctrl.output.StoreRefOutput.schema.json ../../../schemas/rugix-ctrl-output-store-ref.schema.json
cp generated/rugix_ctrl.output.StoreVerifyOutput.schema.json ../../../schemas/rugix-ctrl-output-store-verify.schema.json
cp generated/rugix_ctrl.output.StoreGcOutput.schema.json ../../../schemas/rugix-ctrl-output-store-gc.schema.json
)

(
cd crates/libs/rugix-bundle
mkdir -p generated
rm -rf generated/*
sidex generate json-schema generated/

cp generated/rugix_bundle.manifest.BundleManifest.schema.json ../../../schemas/rugix-bundle-manifest.schema.json
cp generated/rugix_bundle.manifest.AppManifest.schema.json ../../../schemas/rugix-app-manifest.schema.json
cp generated/rugix_bundle.compose.ImageOptions.schema.json ../../../schemas/rugix-compose-image-options.schema.json
cp generated/rugix_bundle.compose.ImageMetadata.schema.json ../../../schemas/rugix-compose-image-metadata.schema.json
)

cargo fmt
