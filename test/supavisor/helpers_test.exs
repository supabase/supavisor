defmodule Supavisor.HelpersTest do
  use ExUnit.Case, async: true
  alias Supavisor.Helpers

  describe "parse_secret/2" do
    test "parses SCRAM-SHA-256 secrets correctly" do
      encoded_stored_key = Base.encode64("storedKey")
      encoded_server_key = Base.encode64("serverKey")
      secret = "SCRAM-SHA-256$4000:salt$#{encoded_stored_key}:#{encoded_server_key}"
      user = "user@example.com"

      expected =
        {:ok,
         %{
           digest: "SCRAM-SHA-256",
           iterations: 4000,
           salt: "salt",
           stored_key: "storedKey",
           server_key: "serverKey",
           user: user
         }}

      assert Helpers.parse_secret(secret, user) == expected
    end

    test "parses md5 secrets correctly" do
      secret = "supersecret"
      user = "user@example.com"
      expected = {:ok, %{digest: :md5, secret: secret, user: user}}
      assert Helpers.parse_secret("md5supersecret", user) == expected
    end

    test "returns error for unsupported or invalid secret formats" do
      assert Helpers.parse_secret("unsupported_secret", "user@example.com") ==
               {:error, "Unsupported or invalid secret format"}
    end
  end
end
