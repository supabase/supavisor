defmodule Supavisor.Secret do
  @moduledoc """
  Behaviour for secret structs used in authentication.

  Each secret type (PasswordSecrets, SASLSecrets, MD5Secrets) implements
  this behaviour to handle its own serialization and method identification.
  """

  @type auth_method :: :password | :auth_query | :auth_query_md5

  @doc """
  Converts a secret struct into a map that can be encoded in JSON.
  """
  @callback to_encodable_map(struct()) :: map()

  @doc """
  Converts a map decoded from JSON into a secret struct.
  """
  @callback from_decoded_map(map()) :: struct()

  @doc """
  Returns the authentication method associated with the secret type.
  """
  @callback auth_method() :: auth_method()
end
