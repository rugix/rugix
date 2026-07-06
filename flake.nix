{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    {
      overlays.default = final: _prev: {
        inherit (self.packages.${final.stdenv.hostPlatform.system})
          rugix-ctrl
          rugix-bundler
          rugix-util
          ;
      };
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        version = self.shortRev or self.dirtyShortRev or "unknown";

        buildRugixPackage =
          name:
          pkgs.rustPlatform.buildRustPackage {
            inherit name;
            src = ./.;
            cargoBuildFlags = [
              "--bin"
              name
            ];
            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.xz ];
            env.RUGIX_GIT_VERSION = version;
            doCheck = false;
          };

        wrapWithXdelta =
          drv:
          pkgs.runCommand drv.name { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
            mkdir -p $out/bin
            for bin in ${drv}/bin/*; do
              makeWrapper "$bin" "$out/bin/$(basename "$bin")" \
                --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.xdelta ]}
            done
          '';
      in
      {
        packages = {
          rugix-ctrl = wrapWithXdelta (buildRugixPackage "rugix-ctrl");
          rugix-bundler = wrapWithXdelta (buildRugixPackage "rugix-bundler");
          rugix-util = buildRugixPackage "rugix-util";
          default = self.packages.${system}.rugix-ctrl;
        };
      }
    );
}
