defmodule Supavisor.JwtTest do
  use ExUnit.Case, async: true
  alias Supavisor.Jwt

  @secret "my_secret_key"
  @wrong_secret "my_wrong_secret_key"

  describe "authorize/2" do
    test "returns claims for a valid token" do
      {:ok, token, _} = create_valid_jwt_token()
      assert {:ok, claims} = Jwt.authorize(token, @secret)
      assert claims["role"] == "test"
    end

    test "raises an error for non-binary token" do
      assert_raise FunctionClauseError, fn ->
        Jwt.authorize(123, @secret)
      end
    end

    test "returns signature_error for a wrong secret" do
      {:ok, token, _} = create_valid_jwt_token()
      assert {:error, :signature_error} = Jwt.authorize(token, @wrong_secret)
    end
  end

  defp create_valid_jwt_token do
    exp = Joken.current_time() + 3600
    claims = %{"role" => "test", "exp" => exp}
    signer = Joken.Signer.create("HS256", @secret)
    Joken.encode_and_sign(claims, signer)
  end
end
