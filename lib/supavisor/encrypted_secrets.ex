defmodule Supavisor.EncryptedSecrets do
  @moduledoc """
  Wraps secret structs (PasswordSecrets, SASLSecrets, MD5Secrets) in an
  AES-256-GCM encrypted binary so they can be sent safely over `:erpc` without
  relying on anonymous function closures (which break when module checksums
  differ across nodes during rolling deploys).
  """

  @derive {Inspect, only: []}

  defstruct [:data]

  @type t :: %__MODULE__{data: binary()}

  alias Supavisor.ClientHandler.Auth.{MD5Secrets, PasswordSecrets, SASLSecrets}

  @aad "supavisor_encrypted_secrets"

  @doc """
  Encrypts a secret struct into an `%EncryptedSecrets{}`.
  """
  @spec encrypt(PasswordSecrets.t() | SASLSecrets.t() | MD5Secrets.t()) :: t()
  def encrypt(%PasswordSecrets{} = s), do: do_encrypt(s)
  def encrypt(%SASLSecrets{} = s), do: do_encrypt(s)
  def encrypt(%MD5Secrets{} = s), do: do_encrypt(s)

  @doc """
  Decrypts an `%EncryptedSecrets{}` back to the original struct.
  """
  @spec decrypt(t()) :: PasswordSecrets.t() | SASLSecrets.t() | MD5Secrets.t()
  def decrypt(%__MODULE__{data: data}) do
    <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>> = data
    key = derive_key()

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, @aad, tag, false) do
      :error -> raise "EncryptedSecrets: decryption failed (tampered or wrong key)"
      json -> from_json(json)
    end
  end

  @doc """
  Decrypts and returns `{method, struct}` where method is derived from the struct type.
  """
  @spec decrypt_with_method(t()) :: {:password | :auth_query | :auth_query_md5, struct()}
  def decrypt_with_method(%__MODULE__{} = encrypted) do
    struct = decrypt(encrypted)
    {derive_method(struct), struct}
  end

  ## Private

  defp do_encrypt(struct) do
    key = derive_key()
    iv = :crypto.strong_rand_bytes(12)
    json = to_json(struct)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, json, @aad, 16, true)

    %__MODULE__{data: <<iv::binary, tag::binary, ciphertext::binary>>}
  end

  defp derive_key do
    secret_key_base =
      Application.get_env(:supavisor, SupavisorWeb.Endpoint)[:secret_key_base]

    :crypto.hash(:sha256, secret_key_base)
  end

  defp derive_method(%PasswordSecrets{}), do: :password
  defp derive_method(%SASLSecrets{}), do: :auth_query
  defp derive_method(%MD5Secrets{}), do: :auth_query_md5

  # JSON serialization

  defp to_json(%PasswordSecrets{user: u, password: p}) do
    Jason.encode!(%{type: "password", user: u, password: p})
  end

  defp to_json(%SASLSecrets{} = s) do
    Jason.encode!(%{
      type: "sasl",
      user: s.user,
      client_key: if(s.client_key, do: Base.encode64(s.client_key)),
      server_key: Base.encode64(s.server_key),
      stored_key: Base.encode64(s.stored_key),
      salt: Base.encode64(s.salt),
      digest: s.digest,
      iterations: s.iterations
    })
  end

  defp to_json(%MD5Secrets{user: u, password: p}) do
    Jason.encode!(%{type: "md5", user: u, password: p})
  end

  defp from_json(json) do
    map = Jason.decode!(json)

    case map["type"] do
      "password" ->
        %PasswordSecrets{user: map["user"], password: map["password"]}

      "sasl" ->
        %SASLSecrets{
          user: map["user"],
          client_key: if(map["client_key"], do: Base.decode64!(map["client_key"])),
          server_key: Base.decode64!(map["server_key"]),
          stored_key: Base.decode64!(map["stored_key"]),
          salt: Base.decode64!(map["salt"]),
          digest: map["digest"],
          iterations: map["iterations"]
        }

      "md5" ->
        %MD5Secrets{user: map["user"], password: map["password"]}
    end
  end
end
