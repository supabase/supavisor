{
  fetchMixDeps,
  fetchurl,
  mixRelease,
  lib,
  stdenv,
  darwin,
  libiconv,
  cacert,
}: let
  pname = "supavisor";
  version = "0.0.1";
  src = ./..;

  mixFodDeps = fetchMixDeps {
    pname = "mix-deps-${pname}";
    inherit src version;
    hash = "sha256-Y7dMy1pjRiqrLIECqxCE5vUCXT/WKAgkndxFHkyEkGs=";
    # git deps fetch over TLS: point git at the Mozilla bundle, as the
    # distro default paths it is compiled with do not exist on non-NixOS
    # hosts (and hex/rebar may not set one either).
    GIT_SSL_CAINFO = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  # Pre-fetched so native/pgparser/Makefile can skip downloading
  # (the nix sandbox has no network access).
  libpgQueryTarball = fetchurl {
    url = "https://github.com/pganalyze/libpg_query/archive/refs/tags/17-6.2.1.tar.gz";
    hash = "sha256-Z4Q01ZURyIksN7pbmBarZBvQB87y7aIVsil8Obechh0=";
  };
in
  mixRelease {
    inherit pname version src mixFodDeps;

    # Used by native/pgparser/Makefile instead of downloading.
    LIBPG_QUERY_TARBALL = libpgQueryTarball;

    buildInputs = lib.optionals stdenv.isDarwin (with darwin.apple_sdk; [
      libiconv
      frameworks.System
      frameworks.CoreFoundation
      frameworks.CoreServices
      frameworks.DiskArbitration
      frameworks.IOKit
      frameworks.CFNetwork
      frameworks.Security
      libs.libDER
    ]);

    meta = {
      mainProgram = "supavisor";
    };
  }
