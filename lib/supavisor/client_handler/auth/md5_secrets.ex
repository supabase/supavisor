defmodule Supavisor.ClientHandler.Auth.MD5Secrets do
  @moduledoc "Secrets for MD5 authentication"

  @derive {Inspect, except: [:password]}
  defstruct [:user, :password]

  @type t :: %__MODULE__{
          user: String.t(),
          password: String.t()
        }
end
