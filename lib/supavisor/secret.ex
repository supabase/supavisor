defmodule Supavisor.Secret do
  @moduledoc """
  Behaviour for secret structs used in authentication.

  Each secret type (PasswordSecrets, SASLSecrets, MD5Secrets) implements
  this behaviour to handle its own serialization and method identification.
  """

  @type auth_method :: :password | :auth_query | :auth_query_md5

  @callback to_encodable_map(struct()) :: map()
  @callback from_decoded_map(map()) :: struct()
  @callback auth_method() :: auth_method()
end
