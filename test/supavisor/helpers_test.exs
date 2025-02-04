defmodule Supavisor.HelpersTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Supavisor.Helpers

  @subject Supavisor.Helpers

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
    test "Prisma migration databases are accepted" do
      assert @subject.validate_name(
               "prisma_migrate_shadow_db_dfe467a1-f7e4-4c27-87de-a930270f4622"
             )
    end

    property "ASCII strings with length within 1..63 are valid" do
      check all name <- string(:ascii, min_length: 1, max_length: 63) do
        assert @subject.validate_name(name)
      end
    end

    property "string that is longer that 63 characters is invalid" do
      check all name <- string(:printable, min_length: 64) do
        refute @subject.validate_name(name)
      end
    end

    property "printable strings with at most 63 *bytes* are valid" do
      check all name <- string(:printable, min_length: 1, max_length: 63) do
        # It is defined in weird way, as it is hard to generate strings with at
        # most 63 bytes, but that test is functionally equivalend
        assert @subject.validate_name(name) == byte_size(name) < 64
      end
    end

    property "non-printable strings are invalid" do
      check all prefix <- string(:utf8), suffix <- string(:utf8) do
        refute @subject.validate_name(prefix <> <<0>>)
        refute @subject.validate_name(<<0>> <> suffix)
        refute @subject.validate_name(prefix <> <<0>> <> suffix)

        refute @subject.validate_name(prefix <> <<0x10>>)
        refute @subject.validate_name(<<0x10>> <> suffix)
        refute @subject.validate_name(prefix <> <<0x10>> <> suffix)
      end
    end
  end
end
