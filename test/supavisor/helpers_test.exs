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

  describe "validate_name/1" do
    test "allows valid unquoted names" do
      assert Helpers.validate_name("valid_name")
      # Minimum length
      assert Helpers.validate_name("a")
      assert Helpers.validate_name("valid_name_123")
      assert Helpers.validate_name("name$123")
    end

    test "rejects invalid unquoted names" do
      # Empty name
      refute Helpers.validate_name("")
      # Starts with a number
      refute Helpers.validate_name("0invalid")
      # Contains uppercase letters
      refute Helpers.validate_name("InvalidName")
      # Contains hyphen
      refute Helpers.validate_name("invalid-name")
      # Contains period
      refute Helpers.validate_name("invalid.name")
      # Over 63 chars
      refute Helpers.validate_name(
               "this_name_is_way_toooooo_long_and_exceeds_sixty_three_characters"
             )
    end

    test "allows valid quoted names" do
      # Contains space
      assert Helpers.validate_name("\"Valid Name\"")
      # Contains uppercase letters
      assert Helpers.validate_name("\"ValidName123\"")
      # Same as unquoted but quoted
      assert Helpers.validate_name("\"valid_name\"")
      # Contains dollar sign
      assert Helpers.validate_name("\"Name with $\"")
      assert Helpers.validate_name("\"name with multiple spaces\"")
    end

    test "rejects invalid quoted names" do
      # Contains hyphen
      refute Helpers.validate_name("\"invalid-name\"")
      # Contains period
      refute Helpers.validate_name("\"invalid.name\"")
      # Empty name
      refute Helpers.validate_name("\"\"")
    end
  end
end
