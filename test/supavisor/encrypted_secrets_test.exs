defmodule Supavisor.EncryptedSecretsTest do
  use ExUnit.Case, async: true

  alias Supavisor.EncryptedSecrets
  alias Supavisor.ClientHandler.Auth.{MD5Secrets, PasswordSecrets, SASLSecrets}

  describe "round-trip encrypt/decrypt" do
    test "PasswordSecrets" do
      original = %PasswordSecrets{user: "alice", password: "s3cret"}
      encrypted = EncryptedSecrets.encrypt(original)
      assert %EncryptedSecrets{} = encrypted
      assert EncryptedSecrets.decrypt(encrypted) == original
    end

    test "SASLSecrets" do
      original = %SASLSecrets{
        user: "bob",
        client_key: :crypto.strong_rand_bytes(32),
        server_key: :crypto.strong_rand_bytes(32),
        stored_key: :crypto.strong_rand_bytes(32),
        salt: :crypto.strong_rand_bytes(16),
        digest: "SCRAM-SHA-256",
        iterations: 4096
      }

      encrypted = EncryptedSecrets.encrypt(original)
      assert %EncryptedSecrets{} = encrypted
      assert EncryptedSecrets.decrypt(encrypted) == original
    end

    test "SASLSecrets with nil client_key" do
      original = %SASLSecrets{
        user: "bob",
        client_key: nil,
        server_key: :crypto.strong_rand_bytes(32),
        stored_key: :crypto.strong_rand_bytes(32),
        salt: :crypto.strong_rand_bytes(16),
        digest: "SCRAM-SHA-256",
        iterations: 4096
      }

      encrypted = EncryptedSecrets.encrypt(original)
      assert EncryptedSecrets.decrypt(encrypted) == original
    end

    test "MD5Secrets" do
      original = %MD5Secrets{user: "carol", password: "md5hash"}
      encrypted = EncryptedSecrets.encrypt(original)
      assert %EncryptedSecrets{} = encrypted
      assert EncryptedSecrets.decrypt(encrypted) == original
    end
  end

  describe "decrypt_with_method/1" do
    test "PasswordSecrets returns :password with all fields" do
      original = %PasswordSecrets{user: "u", password: "p"}
      encrypted = EncryptedSecrets.encrypt(original)

      assert {:password, ^original} = EncryptedSecrets.decrypt_with_method(encrypted)
    end

    test "SASLSecrets returns :auth_query with all fields" do
      original = %SASLSecrets{
        user: "u",
        client_key: <<1, 2, 3>>,
        server_key: <<4, 5, 6>>,
        stored_key: <<7, 8, 9>>,
        salt: <<10, 11, 12>>,
        digest: "SCRAM-SHA-256",
        iterations: 4096
      }

      encrypted = EncryptedSecrets.encrypt(original)

      assert {:auth_query, ^original} = EncryptedSecrets.decrypt_with_method(encrypted)
    end

    test "MD5Secrets returns :auth_query_md5 with all fields" do
      original = %MD5Secrets{user: "u", password: "p"}
      encrypted = EncryptedSecrets.encrypt(original)

      assert {:auth_query_md5, ^original} = EncryptedSecrets.decrypt_with_method(encrypted)
    end
  end

  test "tampered ciphertext raises on decrypt" do
    encrypted = EncryptedSecrets.encrypt(%PasswordSecrets{user: "u", password: "p"})

    # Flip a byte in the ciphertext
    <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>> = encrypted.data
    tampered_ct = :crypto.exor(ciphertext, :binary.copy(<<0xFF>>, byte_size(ciphertext)))
    tampered = %EncryptedSecrets{data: <<iv::binary, tag::binary, tampered_ct::binary>>}

    assert_raise RuntimeError, fn ->
      EncryptedSecrets.decrypt(tampered)
    end
  end
end
