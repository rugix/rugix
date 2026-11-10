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
      nixosModules.rugix = ./nix/modules/rugix.nix;

      lib.mkBundle =
        {
          pkgs,
          rugixBundler ? self.packages.${pkgs.stdenv.buildPlatform.system}.rugix-bundler,
        }:
        pkgs.callPackage ./nix/mk-bundle.nix { inherit rugixBundler; };

      lib.mkComposeBundle =
        {
          pkgs,
          rugixBundler ? self.packages.${pkgs.stdenv.buildPlatform.system}.rugix-bundler,
        }:
        pkgs.callPackage ./nix/mk-compose-bundle.nix { inherit rugixBundler; };

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
              license = with pkgs.lib.licenses; [
                mit
                asl20
              ];
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
        devShells = {
          default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                git
                pkg-config
                openssl
                xz
              ]
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ podman ];
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          packaging = pkgs.mkShell {
            packages = with pkgs; [
              git
              dpkg
              xz
            ];
          };
          system-tests = pkgs.mkShell {
            packages = with pkgs; [
              podman
              qemu
              mtools
              swtpm
              openssl
              skopeo
              xdelta
            ];
            RUGIX_OVMF_CODE_AMD64 = "${pkgs.OVMF.fd}/FV/OVMF_CODE.fd";
            RUGIX_OVMF_VARS_AMD64 = "${pkgs.OVMF.fd}/FV/OVMF_VARS.fd";
          };
        };

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
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          bundle = import ./nix/tests/bundle.nix {
            inherit pkgs;
            mkBundle = self.lib.mkBundle { inherit pkgs; };
          };
          compose-bundle = import ./nix/tests/compose-bundle.nix {
            inherit pkgs;
            mkComposeBundle = self.lib.mkComposeBundle { inherit pkgs; };
          };
        };
      }
    );
}
