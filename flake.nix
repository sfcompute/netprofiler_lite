{
  description = "netprofiler_lite: shareable object storage throughput benchmark";

  nixConfig = {
    extra-substituters = [
      "https://nix-community.cachix.org"
    ];
    extra-trusted-public-keys = [
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUQxH7u0yZ6u5nYzK5vC7g1VQJzY="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    fenix.url = "github:nix-community/fenix";
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        toolchain = fenix.packages.${system}.stable;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = toolchain.cargo;
          rustc = toolchain.rustc;
        };
      in
      {
        packages.default = rustPlatform.buildRustPackage {
          pname = "netprofiler_lite";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;

          nativeBuildInputs = [ pkgs.pkg-config ];
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.pkg-config

            pkgs.awscli2
            pkgs.doppler

            toolchain.cargo
            toolchain.clippy
            toolchain.rustc
            toolchain.rustfmt
          ];
        };

        apps.seed = flake-utils.lib.mkApp {
          drv = pkgs.writeShellApplication {
            name = "seed_artifacts";
            runtimeInputs = [ pkgs.bash pkgs.awscli2 pkgs.coreutils pkgs.doppler ];
            text = ''
              exec bash "${self}/scripts/seed_artifacts.sh" "$@"
            '';
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      });
}
