defmodule Supavisor.JWT.JWKS.StrategyTest do
  # Starts `Supavisor.JWT.JWKS.Strategy` singleton and mutates
  # global `Application` env plus the global Tesla.Mock.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  import Supavisor.Support.JWKSHelper,
    only: [
      default_config: 0,
      default_config: 1,
      generate_rsa_keypair: 0,
      start_jwks_auth: 2,
      faulty_issuer: 0,
      raising_issuer: 0
    ]

  @successful_fetch_event [:joken_jwks, :default_strategy, :signers]
  @exception_fetch_event [:joken_jwks, :http_fetcher, :exception]

  setup_all do
    generate_rsa_keypair()
  end

  setup do
    ref = make_ref()
    pid = self()

    :telemetry.attach_many(
      {ref, :signers},
      [@successful_fetch_event, @exception_fetch_event],
      fn event, measurements, meta, _config -> send(pid, {ref, event, measurements, meta}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach({ref, :signers}) end)

    %{ref: ref}
  end

  test "fetches the JWKS from the issuer's well-known path and reports it", %{
    ref: ref,
    public_jwk: public_jwk
  } do
    start_jwks_auth(default_config(), public_jwk)

    assert_received {^ref, @successful_fetch_event, %{count: 1},
                     %{module: Supavisor.JWT.JWKS.Strategy}}
  end

  test "logs and reports no keys when the issuer answers with a server error", %{
    ref: ref,
    public_jwk: public_jwk
  } do
    log = capture_log(fn -> start_jwks_auth(default_config(faulty_issuer()), public_jwk) end)

    assert log =~ "Failed to fetch signers"
    assert log =~ "jwks_server_http_error"

    refute_received {^ref, @successful_fetch_event, _, _}
    refute_received {^ref, @exception_fetch_event, _, _}
  end

  test "reports an exception when fetching the JWKS raises", %{
    ref: ref,
    public_jwk: public_jwk
  } do
    capture_log(fn ->
      assert_raise RuntimeError, ~r/jwks fetch failed/, fn ->
        start_jwks_auth(default_config(raising_issuer()), public_jwk)
      end
    end)

    assert_received {^ref, @exception_fetch_event, _, %{kind: :error}}
    refute_received {^ref, @successful_fetch_event, _, _}
  end
end
