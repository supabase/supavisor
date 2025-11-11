defmodule Supavisor.ClientHandler.Auth.ManagerSecrets do
  @moduledoc "Secrets for manager user (used by SecretChecker to run auth_query)"

  defstruct [:db_user, :db_password]

  @type t :: %__MODULE__{
          db_user: String.t(),
          db_password: String.t()
        }
end
