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
         %Supavisor.ClientHandler.Auth.SASLSecrets{
           digest: "SCRAM-SHA-256",
           iterations: 4000,
           salt: "salt",
           stored_key: "storedKey",
           server_key: "serverKey",
           client_key: "storedKey",
           user: user
         }}

      assert Helpers.parse_secret(secret, user) == expected
    end

    test "parses md5 secrets correctly" do
      secret = "supersecret"
      user = "user@example.com"

      expected =
        {:ok, %Supavisor.ClientHandler.Auth.MD5Secrets{password: secret, user: user}}

      assert Helpers.parse_secret("md5supersecret", user) == expected
    end

    test "returns error for unsupported or invalid secret formats" do
      assert Helpers.parse_secret("unsupported_secret", "user@example.com") ==
               {:error, "Unsupported or invalid secret format"}
    end
  end

  describe "get_user_secret/3" do
    test "handles Postgrex.Error and extracts postgres error message" do
      db_conf = Application.get_env(:supavisor, Supavisor.Repo)

      {:ok, conn} =
        Postgrex.start_link(
          hostname: db_conf[:hostname],
          port: db_conf[:port],
          database: db_conf[:database],
          password: db_conf[:password],
          username: db_conf[:username]
        )

      # Query references a non-existent table to trigger Postgrex.Error
      invalid_query = "SELECT * FROM nonexistent_table_xyz WHERE user=$1"

      result = Helpers.get_user_secret(conn, invalid_query, "testuser")

      assert {:error, message} = result

      assert message ==
               ~s(Authentication query failed: relation "nonexistent_table_xyz" does not exist)

      GenServer.stop(conn)
    end

    test "handles DBConnection.ConnectionError unreachable database" do
      {:ok, conn} =
        Postgrex.start_link(
          hostname: "invalid.nonexistent.host",
          port: 5432,
          database: "test"
        )

      auth_query = "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1"
      result = Helpers.get_user_secret(conn, auth_query, "testuser")

      assert {:error, message} = result
      assert message == "Authentication query failed: Connection to database not available"

      GenServer.stop(conn)
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

  describe "set_min_heap_size_from_system/1" do
    test "sets the minimum heap size based on a percentage of system memory" do
      total_memory_bytes = :memsup.get_system_memory_data()[:total_memory]
      {:min_heap_size, old_min_heap_words} = Process.info(self(), :min_heap_size)

      # Call the function (returns old min_heap_size value)
      old_value = Helpers.set_min_heap_size_from_system(0.03)
      assert is_integer(old_value)
      assert old_value == old_min_heap_words

      # Verify the new value is reasonable (within 10% of expected)
      {:min_heap_size, new_min_heap_words} = Process.info(self(), :min_heap_size)
      expected_words = div(round(total_memory_bytes * 0.03), :erlang.system_info(:wordsize))

      # Erlang may round up to valid heap sizes, so check it's close to expected
      assert_in_delta new_min_heap_words, expected_words, expected_words * 0.1
    end
  end
end
