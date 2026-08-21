defmodule Supavisor.ClientHandler.ProtocolHelpers do
  @moduledoc """
  Protocol parsing and analysis helpers for client connections.

  This module contains pure business logic for:
  - Startup packet parsing and validation
  - Protocol message analysis and routing
  - Client packet processing
  - Protocol data transformation utilities

  All functions are pure (other than potential logs).
  """

  require Logger

  alias Supavisor.{
    Errors.InvalidUserInfoError,
    Errors.StartupMessageError,
    Errors.MaxPreparedStatementsError,
    Errors.PreparedStatementNotFoundError,
    Errors.SimpleQueryNotSupportedError,
    Errors.DuplicatePreparedStatementError,
    FeatureFlag,
    HandlerHelpers,
    Helpers,
    Protocol.MessageStreamer,
    Protocol.Client
  }

  require Supavisor.Protocol.PreparedStatements, as: PreparedStatements

  @type packet_processing_result ::
          {:ok, MessageStreamer.stream_state(), [PreparedStatements.handled_pkt()] | binary()}
          | {:error, MaxPreparedStatementsError.t()}
          | {:error, SimpleQueryNotSupportedError.t()}
          | {:error, DuplicatePreparedStatementError.t()}
          | {:error, PreparedStatementNotFoundError.t()}

  @type startup_message_data() ::
          {atom(),
           {String.t(), String.t(), String.t() | nil, String.t() | nil, boolean(),
            boolean() | nil, String.t() | nil}}

  ## Startup Packet Processing

  @doc """
  Parses and validates startup packet data.

  Returns parsed user info, application name, and log level if successful.
  """
  @spec parse_startup_packet(binary()) ::
          {:ok, startup_message_data(), String.t() | nil, Logger.level() | nil}
          | {:error, StartupMessageError.t() | InvalidUserInfoError.t()}
  def parse_startup_packet(bin) do
    with {:ok, hello} <- Client.decode_startup_packet(bin),
         {:ok, {type, {user, tenant_or_alias, db_name, search_path, jit, client_tls, client_ip}}} <-
           extract_and_validate_user_info(hello.payload) do
      Logger.debug("ClientHandler: Client startup message: #{inspect(hello)}")
      app_name = normalize_app_name(hello.payload["application_name"])
      log_level = extract_log_level(hello)

      {:ok, {type, {user, tenant_or_alias, db_name, search_path, jit, client_tls, client_ip}},
       app_name, log_level}
    end
  end

  @doc """
  Extracts and validates user information from startup payload.
  """
  @spec extract_and_validate_user_info(map()) ::
          {:ok, startup_message_data()}
          | {:error, InvalidUserInfoError.t()}
  def extract_and_validate_user_info(payload) do
    {type, {user, tenant_or_alias, db_name}} = HandlerHelpers.parse_user_info(payload)

    if Helpers.validate_name(user) and (is_nil(db_name) or Helpers.validate_name(db_name)) do
      options = payload["options"] || %{}
      search_path = payload["search_path"] || options["search_path"]
      jit = options["jit"] == "true"
      client_tls = options["client_tls"] && options["client_tls"] == "true"
      client_ip = parse_ip_address(options["client_ip"])

      {:ok, {type, {user, tenant_or_alias, db_name, search_path, jit, client_tls, client_ip}}}
    else
      {:error, %InvalidUserInfoError{user: user, db_name: db_name}}
    end
  end

  @doc """
  Resolves the peer address for a connection.

  Forwarded addresses are trusted only on local listeners used for inter-node proxying.
  """
  @spec resolve_peer_ip(String.t(), String.t() | nil, boolean()) :: String.t()
  def resolve_peer_ip(_socket_peer_ip, client_ip, true) when is_binary(client_ip), do: client_ip
  def resolve_peer_ip(socket_peer_ip, _client_ip, _local), do: socket_peer_ip

  defp parse_ip_address(address) when is_binary(address) do
    case :inet.parse_address(String.to_charlist(address)) do
      {:ok, parsed} -> parsed |> :inet.ntoa() |> List.to_string()
      {:error, _reason} -> nil
    end
  end

  defp parse_ip_address(_address), do: nil

  ## Client Packet Processing

  @doc """
  Processes client packets for prepared statements based on mode and feature flags.

  Returns processed packets or passes through unchanged based on configuration.
  """
  @spec process_client_packets(binary(), atom(), map()) :: packet_processing_result()
  def process_client_packets(
        bin,
        :transaction,
        %{tenant_feature_flags: tenant_feature_flags} = data
      ) do
    translate? = FeatureFlag.enabled?(tenant_feature_flags, "named_prepared_statements")

    stream_state =
      MessageStreamer.update_state(data.stream_state, &%{&1 | translate?: translate?})

    MessageStreamer.handle_packets(stream_state, bin)
  end

  def process_client_packets(bin, _mode, data) do
    {:ok, data.stream_state, bin}
  end

  ## Protocol Utilities

  @doc """
  Normalizes application name from client connection.

  Returns sanitized string or default "" for missing/invalid names.
  """
  @spec normalize_app_name(any()) :: String.t()
  def normalize_app_name(name) when is_binary(name), do: name
  def normalize_app_name(nil), do: ""

  def normalize_app_name(name) do
    Logger.debug("ClientHandler: Invalid application name #{inspect(name)}")
    ""
  end

  @doc """
  Extracts log level from startup message options.

  Returns atom log level or nil if not specified or invalid.
  """
  @spec extract_log_level(map()) :: atom() | nil
  def extract_log_level(%{payload: %{"options" => options}}) do
    level = options["log_level"] && String.to_existing_atom(options["log_level"])

    if level in [:debug, :info, :notice, :warning, :error] do
      level
    else
      nil
    end
  end

  def extract_log_level(_), do: nil
end
