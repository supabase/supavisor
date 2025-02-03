{
  description = "Elixir's application";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
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

        packages = {
          # Expose Devenv supervisor
          devenv-up = self'.devShells.default.config.procfileScript;
        };

        devShells.default = devenv.lib.mkShell {
          inherit inputs pkgs;

          modules = [
            {
              pre-commit.hooks = {
                alejandra.enable = true;
                typos = {
                  enable = true;
                  excludes = [
                    "test/integration/"
                  ];
                };
              };
            }
            {
              languages.elixir = {
                enable = true;
                package = pkgs.beam27Packages.elixir_1_18;
              };
              packages = [
                pkgs.lexical
              ];

              pre-commit.hooks = {
                mix-format.enable = true;
                # credo.enable = true;
              };

              # env.DYLD_INSERT_LIBRARIES = "${pkgs.mimalloc}/lib/libmimalloc.dylib";
            }
            {
              packages = [
                pkgs.pgbouncer
              ];

              services.postgres = {
                enable = true;
                package = pkgs.postgresql_15;
                initialScript = ''
                  ${builtins.readFile ./dev/postgres/00-setup.sql}

                  CREATE USER postgres SUPERUSER PASSWORD 'postgres';
                '';
                listen_addresses = "127.0.0.1";
                port = 6432;
                settings = {
                  max_prepared_transactions = 262143;
                };
              };

              process.manager.implementation = "honcho";

              # Force connection through TCP instead of Unix socket
              env.PGHOST = lib.mkForce "";
            }
            {
              languages.javascript = {
                enable = true;
                bun.enable = true;
                yarn.enable = true;
              };
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
