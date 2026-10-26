defmodule Supavisor.JWT.JWKS.AlgFixupTest do
  use ExUnit.Case, async: true

  alias Supavisor.JWT.JWKS.AlgFixup

  @rsa_key %{"kty" => "RSA", "use" => "sig", "kid" => "rsa-1", "n" => "bW9kdWx1cw", "e" => "AQAB"}
  @ec_key %{
    "kty" => "EC",
    "use" => "sig",
    "kid" => "ec-1",
    "alg" => "ES384",
    "crv" => "P-384",
    "x" => "eA",
    "y" => "eQ"
  }

  # `AlgFixup.call/3` runs the rest of the middleware stack with `Tesla.run/2`
  # and fixes the response body it gets back. An empty stack returns the env
  # unchanged, so seeding `body` stands in for the adapter's response.
  defp call_with_body(body), do: AlgFixup.call(%Tesla.Env{body: body}, [], [])

  test "adds alg to an RSA key without one, in a raw JSON body, returning a decoded map" do
    body = JSON.encode!(%{"keys" => [@rsa_key, @ec_key]})

    assert {:ok, %Tesla.Env{body: %{"keys" => [rsa, ec]}}} = call_with_body(body)
    assert rsa == Map.put(@rsa_key, "alg", "RS256")
    assert ec == @ec_key
  end

  test "fixes an already-decoded map body the same way" do
    assert {:ok, %Tesla.Env{body: %{"keys" => [rsa, ec]}}} =
             call_with_body(%{"keys" => [@rsa_key, @ec_key]})

    assert rsa == Map.put(@rsa_key, "alg", "RS256")
    assert ec == @ec_key
  end

  test "leaves an RSA key that already has an alg alone" do
    key = Map.put(@rsa_key, "alg", "RS384")

    assert {:ok, %Tesla.Env{body: %{"keys" => [^key]}}} = call_with_body(%{"keys" => [key]})
  end

  test "passes through bodies without keys, and invalid JSON" do
    assert {:ok, %Tesla.Env{body: %{"other" => 1}}} = call_with_body(%{"other" => 1})
    assert {:ok, %Tesla.Env{body: "not json"}} = call_with_body("not json")
    assert {:ok, %Tesla.Env{body: nil}} = call_with_body(nil)
  end

  test "propagates a failing request untouched" do
    next = [{:fn, fn _env -> {:error, :econnrefused} end}]

    assert {:error, :econnrefused} = AlgFixup.call(%Tesla.Env{}, next, [])
  end
end
