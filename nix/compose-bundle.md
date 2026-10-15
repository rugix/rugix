# Build Container Apps with Nix

`rugix.lib.mkComposeBundle` packages Nix-built Docker image archives as a Rugix
Compose app. It invokes Rugix Bundler and Skopeo inside the Nix build sandbox;
packaging needs neither a running container daemon nor a registry. Each image
becomes a separate bundle payload, and the packaged Compose file uses
content-based Rugix image tags with `pull_policy: never`.

## Create an App Package

In a flake with `nixpkgs` and `rugix` inputs:

```nix
let
  pkgs = nixpkgs.legacyPackages.x86_64-linux;
  mkComposeBundle = rugix.lib.mkComposeBundle { inherit pkgs; };
  image = pkgs.dockerTools.buildLayeredImage {
    name = "example-web";
    tag = "1";
    contents = [ pkgs.python3Minimal ];
    config.Cmd = [ "/bin/python3" "-m" "http.server" "8080" ];
  };
in
mkComposeBundle {
  name = "example-web";
  version = "1";
  platform = "linux/amd64";
  compose.services.web = {
    image = "example-web:1";
    ports = [ "127.0.0.1:8080:8080" ];
  };
  images.web = image;
}
```

The result contains `example-web.rugixb` and `example-web.rugixb-hash`. The hash
can be passed to `rugix-ctrl apps install --bundle-hash` to verify installation.

## Build and Target Platforms

The helper runs on the build machine while the images contain programs for the
target device. Pass the build machine's package set as `pkgs` and build each image
for the target device.
Cross-architecture image builds may require a compatible Linux builder. The
helper never runs the target container.

## Helper Arguments

First call `rugix.lib.mkComposeBundle { pkgs = buildPkgs; }` to obtain the builder.
A custom `rugixBundler` package can also be supplied at this step. Set
`rugix.inputs.nixpkgs.follows = "nixpkgs"` in the flake inputs to share the package set.

| Argument             | Purpose                                                                           |
| -------------------- | --------------------------------------------------------------------------------- |
| `name`               | Rugix app identifier and output filename stem.                                    |
| `version`            | Nix derivation version. Set application/component versions in their metadata too. |
| `compose`            | Compose configuration as a Nix attribute set.                                     |
| `images`             | Docker archive derivations or paths, keyed by Compose service name.               |
| `components`         | Optional list of component TOML/JSON files or directories.                        |
| `metadata`           | Optional app metadata attribute set.                                              |
| `platform`           | Optional target platform, such as `linux/arm64`.                                  |
| `healthCheckTimeout` | Seconds to wait for Compose health checks; defaults to 120.                       |
| `imageLocation`      | Where the device keeps images, `"store"` (default) or `"file"`.                   |

With `"store"`, the device keeps images in its content-addressed store. With
`"file"`, it writes them as files into the generation directory. Use `"file"` while
devices may roll back to a Rugix Ctrl version without the store, which cannot read
images kept in the store.

Every service must have an entry in `images`. Compose `build` entries are rejected:
Nix owns image construction. Archives must contain one image, and their paths
must not contain colons. `composeFile` and `images` are available as passthru
attributes for inspection.

## Test Archive Bundling

```console
nix build .#checks.x86_64-linux.compose-bundle
```

The check creates a real container archive, bundles and unpacks it, and verifies
content tags, image metadata, preserved tags with pinning disabled, and failure
when an archive is missing.
