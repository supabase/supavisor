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

  describe "token_matches/1" do
    test "supabase pat is recognised" do
      assert @subject.token_matches?("sbp_dfe467a1-f7e4-4c27-87de-a930270f4622")
    end

    test "JWT is recognised" do
      assert @subject.token_matches?(
               "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
             )
    end
  end
end

defmodule Supavisor.HelpersJitAuthTest do
  use ExUnit.Case, async: true

  alias Supavisor.Helpers

  @subject Supavisor.Helpers

  describe "check_user_has_jit_role/4" do
    test "returns {:ok, true} when user has role" do
      Req.Test.stub(TestStubReq, fn conn ->
        Plug.Conn.put_status(conn, 200)
        |> Req.Test.json(%{
          "user_role" => %{"role" => "postgres"}
        })
      end)

      assert {:ok, true} =
               @subject.check_user_has_jit_role(
                 "https://fake.url",
                 "fake-token",
                 "postgres",
                 "10.0.0.1",
                 plug: {Req.Test, TestStubReq}
               )
    end

    test "returns {:error, :unauthorized_or_forbidden} when 401 or 403" do
      Req.Test.stub(TestStubReq, fn conn ->
        Plug.Conn.put_status(conn, 401)
        |> Req.Test.json(%{
          "message" => "unauthorized"
        })
      end)

      assert {:error, :unauthorized_or_forbidden} =
               @subject.check_user_has_jit_role(
                 "https://fake.url",
                 "fake-token",
                 "postgres",
                 "10.0.0.1",
                 plug: {Req.Test, TestStubReq}
               )

      Req.Test.stub(TestStubReq, fn conn ->
        Plug.Conn.put_status(conn, 403)
        |> Req.Test.json(%{
          "message" => "unauthorized"
        })
      end)

      assert {:error, :unauthorized_or_forbidden} =
               @subject.check_user_has_jit_role(
                 "https://fake.url",
                 "fake-token",
                 "postgres",
                 "10.0.0.1",
                 plug: {Req.Test, TestStubReq}
               )
    end

    test "returns {:error, {:unexpected_status, status}} on all other status" do
      Req.Test.stub(TestStubReq, fn conn ->
        Plug.Conn.put_status(conn, 500)
        |> Req.Test.json(%{
          "message" => "internal server error"
        })
      end)

      assert {:error, {:unexpected_status, 500}} =
               @subject.check_user_has_jit_role(
                 "https://fake.url",
                 "fake-token",
                 "postgres",
                 "10.0.0.1",
                 plug: {Req.Test, TestStubReq}
               )
    end
  end
end
