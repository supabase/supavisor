defmodule Supavisor.JWT.SharedSecretTest do
  use ExUnit.Case, async: true

  alias Supavisor.JWT.SharedSecret
  alias Supavisor.JWT.SharedSecret.Token

  @secret "my_secret_key"

  describe "verify/2" do
    test "returns the claims of a valid token" do
      token = Token.gen!(%{"role" => "test"}, @secret)

      assert {:ok, claims} = SharedSecret.verify(token, @secret)
      assert claims["role"] == "test"
    end

    test "accepts every HMAC algorithm it advertises" do
      for alg <- SharedSecret.algorithms() do
        token = Token.gen!(%{"role" => "test"}, Joken.Signer.create(alg, @secret))
        assert {:ok, %{"role" => "test"}} = SharedSecret.verify(token, @secret)
      end
    end

    test "rejects a wrong secret" do
      token = Token.gen!(%{"role" => "test"}, @secret)

      assert {:error, :signature_error} = SharedSecret.verify(token, "my_wrong_secret_key")
    end

    test "rejects an expired token" do
      exp = Joken.current_time() - 10
      token = Token.gen!(%{"role" => "test", "exp" => exp}, @secret)

      assert {:error, [message: "Invalid token", claim: "exp", claim_val: ^exp]} =
               SharedSecret.verify(token, @secret)
    end

    test "rejects a non-numeric exp, which would otherwise compare greater than any time" do
      for exp <- ["never", nil, true, [1]] do
        token = Token.gen!(%{"role" => "test", "exp" => exp}, @secret)

        assert {:error, [message: "Invalid token", claim: "exp", claim_val: ^exp]} =
                 SharedSecret.verify(token, @secret)
      end
    end

    test "rejects a token that isn't a JWT" do
      assert {:error, :expected_header_map} = SharedSecret.verify("not-a-jwt", @secret)
    end

    test "rejects a non-HMAC alg (no signer is built for it)" do
      encode = &Base.url_encode64(JSON.encode!(&1), padding: false)
      # The signature is never checked: no signer is built for an RS256 header.
      fake_signature = Base.url_encode64("sig", padding: false)
      token = "#{encode.(%{"alg" => "RS256", "typ" => "JWT"})}.#{encode.(%{})}.#{fake_signature}"

      assert {:error, :error_generating_signer} = SharedSecret.verify(token, @secret)
    end

    test "fails closed for a non-binary token" do
      assert {:error, :token_not_a_string} = SharedSecret.verify(123, @secret)
    end
  end
end
