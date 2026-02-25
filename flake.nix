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
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        pkgVersion = cargoToml.package.version;
      in
      {
        packages.default = rustPlatform.buildRustPackage {
          pname = "netprofiler_lite";
          version = pkgVersion;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;

          nativeBuildInputs = [ pkgs.pkg-config ];
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        apps.bench = flake-utils.lib.mkApp {
          drv = pkgs.writeShellApplication {
            name = "netprofiler_lite_bench";
            runtimeInputs = [ pkgs.coreutils ];
            text = ''
              exec "${self.packages.${system}.default}/bin/netprofiler_lite" \
                --backends "https://pub-0323b6896e3e42cb8971495d2f9a2370.r2.dev,https://pub-c02404be13b644a1874a29231dfbe0d2.r2.dev" \
                --direction download \
                --concurrency 256 \
                --duration 15 \
                --prefix data-8m \
                --file-count 100 \
                --file-size-mb 8 \
                "$@"
            '';
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.pkg-config

            pkgs.awscli2
            pkgs.curl
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
            runtimeInputs = [ pkgs.bash pkgs.awscli2 pkgs.coreutils pkgs.curl pkgs.doppler ];
            text = ''
              exec bash "${self}/scripts/seed_artifacts.sh" "$@"
            '';
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      });
}
