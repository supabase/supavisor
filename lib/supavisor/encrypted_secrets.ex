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

  @type_to_module %{
    "password" => PasswordSecrets,
    "sasl" => SASLSecrets,
    "md5" => MD5Secrets
  }

  @module_to_type Map.new(@type_to_module, fn {k, v} -> {v, k} end)

  @doc """
  Encrypts a secret struct into an `%EncryptedSecrets{}`.
  """
  @spec encrypt(PasswordSecrets.t() | SASLSecrets.t() | MD5Secrets.t()) :: t()
  def encrypt(%module{} = secret) do
    key = derive_key()
    iv = :crypto.strong_rand_bytes(12)

    json =
      secret
      |> module.to_encodable_map()
      |> Map.put(:type, Map.fetch!(@module_to_type, module))
      |> Jason.encode!()

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, json, @aad, 16, true)

    %__MODULE__{data: <<iv::binary, tag::binary, ciphertext::binary>>}
  end

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
    %module{} = struct = decrypt(encrypted)
    {module.auth_method(), struct}
  end

  ## Private

  defp derive_key do
    secret_key_base =
      Application.get_env(:supavisor, SupavisorWeb.Endpoint)[:secret_key_base]

    :crypto.hash(:sha256, secret_key_base)
  end

  defp from_json(json) do
    map = Jason.decode!(json)
    module = Map.fetch!(@type_to_module, map["type"])
    module.from_decoded_map(map)
  end
end
