defmodule Supavisor.ClientHandler.Auth.JitTokenSecrets do
  @moduledoc """
  Secrets for JIT authentication using tokens (JWT/PAT).

  When a client provides a token for JIT authentication, it's validated via the JIT API
  and then sent to PostgreSQL as a cleartext password (expecting PAM authentication).
  """

  @derive {Inspect, except: [:token]}
  defstruct [:user, :token]

  @type t :: %__MODULE__{
          user: String.t(),
          token: String.t()
        }
end
