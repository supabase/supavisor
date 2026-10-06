defmodule Supavisor.ClientHandler.StartupParams do
  @moduledoc """
  Connection parameters parsed from a client's startup packet.
  """

  @type t :: %__MODULE__{
          type: :single | :cluster,
          user: String.t(),
          tenant_or_alias: String.t() | nil,
          db_name: String.t() | nil,
          search_path: String.t() | nil,
          jit: boolean(),
          client_tls: boolean() | nil,
          client_ip: String.t() | nil,
          app_name: String.t() | nil,
          log_level: Logger.level() | nil,
          invalid_options: [{String.t(), String.t()}]
        }

  @enforce_keys [:type, :user]
  defstruct [
    :type,
    :user,
    :tenant_or_alias,
    :db_name,
    :search_path,
    :client_tls,
    :client_ip,
    :app_name,
    :log_level,
    jit: false,
    invalid_options: []
  ]
end
