{
  lib,
  runCommand,
  writeShellScriptBin,
  formats,
  skopeo,
  rugixBundler,
}:

# Bundle Nix-built Docker archives without a registry or container daemon.
{
  name,
  version,
  compose,
  images,
  components ? [ ],
  metadata ? { },
  platform ? null,
  healthCheckTimeout ? 120,
  imageLocation ? "store",
}:

assert lib.assertMsg (
  builtins.attrNames images == builtins.attrNames compose.services
) "mkComposeBundle requires one image archive for every Compose service";
assert lib.assertMsg (lib.all (service: !(service ? build)) (
  builtins.attrValues compose.services
)) "mkComposeBundle accepts Nix-built image archives; remove Compose build entries";

let
  composeFile = (formats.json { }).generate "${name}-compose.json" (
    compose
    // {
      services = lib.mapAttrs (
        serviceName: service:
        service
        // {
          x-rugix = (service.x-rugix or { }) // {
            image = {
              source = "docker-archive";
              ref = toString images.${serviceName};
            };
          };
        }
      ) compose.services;
    }
  );
  # Nix supplies trusted local archives; registry transports stay disabled.
  policyFile = (formats.json { }).generate "archive-policy.json" {
    default = [ { type = "reject"; } ];
    transports.docker-archive."" = [ { type = "insecureAcceptAnything"; } ];
  };
  archiveSkopeo = writeShellScriptBin "skopeo" ''
    exec ${skopeo}/bin/skopeo --policy ${policyFile} "$@"
  '';
  metadataFile = (formats.json { }).generate "${name}-metadata.json" metadata;
  flags = [
    "--app"
    name
    "--health-check-timeout"
    (toString healthCheckTimeout)
    "--metadata-file"
    (toString metadataFile)
  ]
  ++ lib.optionals (platform != null) [
    "--platform"
    platform
  ]
  ++ [
    "--image-location"
    imageLocation
  ]
  ++ lib.concatMap (component: [
    "--components"
    (toString component)
  ]) components;
in
runCommand "${name}-${version}"
  {
    nativeBuildInputs = [
      rugixBundler
      archiveSkopeo
    ];
    passthru = { inherit composeFile images; };
  }
  ''
    mkdir -p "$out"
    rugix-bundler apps pack docker-compose \
      ${lib.escapeShellArgs flags} \
      ${composeFile} \
      "$out"/${lib.escapeShellArg "${name}.rugixb"} \
      > "$out"/${lib.escapeShellArg "${name}.rugixb-hash"}
  ''
