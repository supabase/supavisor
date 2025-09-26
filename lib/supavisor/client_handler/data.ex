defmodule Supavisor.ClientHandler.Data do
  @moduledoc """
  Data structure for ClientHandler gen_statem.
  """

  defstruct [
    :id,
    :sock,
    :trans,
    :peer_ip,
    :local,
    :ssl,
    :auth_context,
    :auth_secrets,
    :auth,
    :tenant,
    :tenant_feature_flags,
    :tenant_availability_zone,
    :user,
    :db_name,
    :app_name,
    :log_level,
    :db_connection,
    :pool,
    :manager,
    :mode,
    :proxy_type,
    :query_start,
    :last_query,
    :timeout,
    :ps,
    :stream_state,
    :stats,
    :idle_timeout,
    :heartbeat_interval,
    :connection_start,
    :state_entered_at,
    :subscribe_retries
  ]
end
