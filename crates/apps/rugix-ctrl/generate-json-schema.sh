#!/usr/bin/env bash

mkdir -p generated
rm -rf generated/*
sidex generate json-schema generated/

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
