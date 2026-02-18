defmodule Supavisor.ClientHandler.Auth.SASLSecrets do
  @moduledoc "Secrets for SCRAM-SHA-256 authentication"

  @behaviour Supavisor.Secret

  @derive {Inspect, except: [:client_key, :server_key, :salt, :stored_key]}
  defstruct [:user, :client_key, :server_key, :digest, :iterations, :salt, :stored_key]

  @type t :: %__MODULE__{
          user: String.t(),
          client_key: binary() | nil,
          server_key: binary(),
          digest: String.t(),
          iterations: pos_integer(),
          salt: binary(),
          stored_key: binary()
        }

  @impl true
  def to_encodable_map(%__MODULE__{} = s) do
    %{
      user: s.user,
      client_key: if(s.client_key, do: Base.encode64(s.client_key)),
      server_key: Base.encode64(s.server_key),
      stored_key: Base.encode64(s.stored_key),
      salt: Base.encode64(s.salt),
      digest: s.digest,
      iterations: s.iterations
    }
  end

  @impl true
  def from_decoded_map(map) do
    %__MODULE__{
      user: map["user"],
      client_key: if(map["client_key"], do: Base.decode64!(map["client_key"])),
      server_key: Base.decode64!(map["server_key"]),
      stored_key: Base.decode64!(map["stored_key"]),
      salt: Base.decode64!(map["salt"]),
      digest: map["digest"],
      iterations: map["iterations"]
    }
  end

  @impl true
  def auth_method, do: :auth_query
end
