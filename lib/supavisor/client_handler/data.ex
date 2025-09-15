defmodule Supavisor.ClientHandler.Data do
  @moduledoc """
  Data structure and utilities for ClientHandler gen_statem.
  """

  alias Supavisor.Protocol.{FrontendMessageHandler, MessageStreamer}

  @type db_connection :: {pid() | nil, pid(), Supavisor.sock()} | nil
  @type auth_context :: map() | nil
  @type auth_secrets :: {atom(), function()} | nil

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
    :active_count,
    :idle_timeout,
    :heartbeat_interval,
    :connection_start,
    :state_entered_at,
    :subscribe_retries
  ]

  @type t :: %__MODULE__{
          id: Supavisor.id() | nil,
          sock: Supavisor.sock(),
          trans: module(),
          peer_ip: String.t(),
          local: boolean(),
          ssl: boolean(),
          auth_context: auth_context(),
          auth_secrets: auth_secrets(),
          auth: map(),
          tenant: String.t() | nil,
          tenant_feature_flags: map() | nil,
          tenant_availability_zone: String.t() | nil,
          user: String.t() | nil,
          db_name: String.t() | nil,
          app_name: String.t() | nil,
          log_level: atom() | nil,
          db_connection: db_connection(),
          pool: pid() | nil,
          manager: reference() | nil,
          mode: atom(),
          proxy_type: atom() | nil,
          query_start: integer() | nil,
          last_query: binary() | nil,
          timeout: integer() | nil,
          ps: any() | nil,
          stream_state: MessageStreamer.stream_state(),
          stats: map(),
          active_count: integer(),
          idle_timeout: integer(),
          heartbeat_interval: integer(),
          connection_start: integer(),
          state_entered_at: integer(),
          subscribe_retries: integer()
        }

  @spec new(Supavisor.sock(), module(), String.t(), boolean(), atom()) :: t()
  def new(sock, trans, peer_ip, local, mode) do
    now = System.monotonic_time()

    %__MODULE__{
      id: nil,
      sock: sock,
      trans: trans,
      peer_ip: peer_ip,
      local: local,
      ssl: false,
      auth_context: nil,
      auth_secrets: nil,
      auth: %{},
      tenant: nil,
      tenant_feature_flags: nil,
      tenant_availability_zone: nil,
      user: nil,
      db_name: nil,
      app_name: nil,
      log_level: nil,
      db_connection: nil,
      pool: nil,
      manager: nil,
      mode: mode,
      proxy_type: nil,
      query_start: nil,
      last_query: nil,
      timeout: nil,
      ps: nil,
      stream_state: MessageStreamer.new_stream_state(FrontendMessageHandler),
      stats: %{},
      active_count: 0,
      idle_timeout: 0,
      heartbeat_interval: 0,
      connection_start: now,
      state_entered_at: now,
      subscribe_retries: 0
    }
  end

  @spec set_tenant_info(t(), map(), String.t(), Supavisor.id(), String.t() | nil, atom()) :: t()
  def set_tenant_info(data, info, user, id, db_name, mode) do
    proxy_type =
      if info.tenant.require_user,
        do: :password,
        else: :auth_query

    auth = %{
      application_name: data.app_name || "Supavisor",
      database: db_name,
      host: to_charlist(info.tenant.db_host),
      sni_hostname:
        if(info.tenant.sni_hostname != nil, do: to_charlist(info.tenant.sni_hostname)),
      port: info.tenant.db_port,
      user: user,
      password: info.user.db_password,
      require_user: info.tenant.require_user,
      upstream_ssl: info.tenant.upstream_ssl,
      upstream_tls_ca: info.tenant.upstream_tls_ca,
      upstream_verify: info.tenant.upstream_verify
    }

    %{
      data
      | id: id,
        tenant: info.tenant.external_id,
        tenant_feature_flags: info.tenant.feature_flags,
        tenant_availability_zone: info.tenant.availability_zone,
        user: user,
        db_name: db_name,
        mode: mode,
        timeout: info.user.pool_checkout_timeout,
        ps: info.tenant.default_parameter_status,
        proxy_type: proxy_type,
        heartbeat_interval: info.tenant.client_heartbeat_interval * 1000,
        auth: auth
    }
  end
end
