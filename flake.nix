{
  description = "Elixir's application";

  inputs.nixpkgs.url = "flake:nixpkgs";
  inputs.flake-parts.url = "github:hercules-ci/flake-parts";

  inputs.devenv = {
    url = "github:cachix/devenv";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    flake-parts,
    devenv,
    ...
  } @ inputs:
    flake-parts.lib.mkFlake {inherit inputs;} {
      flake = {};

      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem = {
        self',
        inputs',
        pkgs,
        lib,
        ...
      }: {
        formatter = pkgs.alejandra;

        apps.up = {
          type = "app";
          program = toString self'.devShells.default.config.procfileScript;
        };

        packages = {
          supavisor = let
            erl = pkgs.beam_nox.packages.erlang_26;
          in erl.callPackage ./nix/package.nix {};

          default = self'.packages.supavisor;
        };

        devShells.default = devenv.lib.mkShell {
          inherit inputs pkgs;

          modules = [
            {
              languages.elixir = {
                enable = true;
                package = pkgs.beam.packages.erlang_26.elixir_1_17;
              };
              packages = [
                pkgs.lexical
              ];

              # env.DYLD_INSERT_LIBRARIES = "${pkgs.mimalloc}/lib/libmimalloc.dylib";
            }
            {
              packages = [
                pkgs.pgbouncer
              ];

              services.postgres = {
                enable = true;
                initialScript = ''
                  ${builtins.readFile ./dev/postgres/00-setup.sql}

                  CREATE USER postgres SUPERUSER PASSWORD 'postgres';
                '';
                listen_addresses = "127.0.0.1";
                port = 6432;
              };

              # Force connection through TCP instead of Unix socket
              env.PGHOST = lib.mkForce "";
            }
            ({
              pkgs,
              lib,
              config,
              ...
            }: {
              languages.rust.enable = true;
              languages.cplusplus.enable = true;

              packages =
                [
                  pkgs.protobuf
                  pkgs.cargo-outdated
                ]
                ++ lib.optionals pkgs.stdenv.isDarwin (with pkgs.darwin.apple_sdk; [
                  frameworks.System
                  frameworks.CoreFoundation
                  frameworks.CoreServices
                  frameworks.DiskArbitration
                  frameworks.IOKit
                  frameworks.CFNetwork
                  frameworks.Security
                  libs.libDER
                ]);

              # Workaround for https://github.com/rust-lang/cargo/issues/5376
              env.RUSTFLAGS = lib.mkForce (lib.optionals pkgs.stdenv.isDarwin [
                "-L framework=${config.devenv.profile}/Library/Frameworks"
                "-C link-arg=-undefined"
                "-C link-arg=dynamic_lookup"
              ]);
            })
          ];
        };
      };
    };
}
