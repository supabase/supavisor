defmodule Supavisor.ClientHandler.Auth.PasswordSecrets do
  @moduledoc "Secrets for password authentication (plaintext password)"

  @behaviour Supavisor.Secret

  @derive {Inspect, except: [:password]}
  defstruct [:user, :password]

  @type t :: %__MODULE__{
          user: String.t(),
          password: String.t()
        }

  @impl true
  def to_encodable_map(%__MODULE__{user: u, password: p}), do: %{user: u, password: p}

  @impl true
  def from_decoded_map(map), do: %__MODULE__{user: map["user"], password: map["password"]}

  @impl true
  def auth_method, do: :password
end
