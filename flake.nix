{
  description = "Rugix system update tools";

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
            pname = name;
            inherit version;
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
            meta = {
              description = "Rugix system update tool: ${name}";
              homepage = "https://rugix.org";
              license = with pkgs.lib.licenses; [ mit asl20 ];
              mainProgram = name;
            };
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

        apps = {
          rugix-ctrl = {
            type = "app";
            program = "${self.packages.${system}.rugix-ctrl}/bin/rugix-ctrl";
            meta.description = "Run Rugix Ctrl";
          };
          rugix-bundler = {
            type = "app";
            program = "${self.packages.${system}.rugix-bundler}/bin/rugix-bundler";
            meta.description = "Run Rugix Bundler";
          };
          rugix-util = {
            type = "app";
            program = "${self.packages.${system}.rugix-util}/bin/rugix-util";
            meta.description = "Run Rugix Util";
          };
          default = self.apps.${system}.rugix-ctrl;
        };

        checks = {
          inherit (self.packages.${system})
            rugix-ctrl
            rugix-bundler
            rugix-util
            ;
        };
      }
    );
}
