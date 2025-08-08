defmodule Supavisor.ClientHandler.Auth.PasswordSecrets do
  @moduledoc "Secrets for password authentication (plaintext password)"

  @derive {Inspect, except: [:password]}
  defstruct [:user, :password]

  @type t :: %__MODULE__{
          user: String.t(),
          password: String.t(),
          use_jit: Bool.t(),
          jit_api_url: String.t()
        }
end
