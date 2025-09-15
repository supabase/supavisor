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
    FeatureFlag,
    HandlerHelpers,
    Helpers,
    Protocol.MessageStreamer,
    Protocol.Server
  }

  require Supavisor.Protocol.PreparedStatements, as: PreparedStatements

  @type startup_result ::
          {:ok, {atom(), {String.t(), String.t(), String.t() | nil, String.t() | nil}},
           String.t(), atom() | nil}
          | {:error, term()}

  @type packet_processing_result ::
          {:ok, MessageStreamer.stream_state(), [PreparedStatements.handled_pkt()] | binary()}
          | {:error, :max_prepared_statements}
          | {:error, :max_prepared_statements_memory}
          | {:error, :prepared_statement_on_simple_query}
          | {:error, :duplicate_prepared_statement, PreparedStatements.statement_name()}
          | {:error, :prepared_statement_not_found, PreparedStatements.statement_name()}

  ## Startup Packet Processing

  @doc """
  Parses and validates startup packet data.

  Returns parsed user info, application name, and log level if successful.
  """
  @spec parse_startup_packet(binary()) :: startup_result()
  def parse_startup_packet(bin) do
    case Server.decode_startup_packet(bin) do
      {:ok, hello} ->
        Logger.debug("ClientHandler: Client startup message: #{inspect(hello)}")

        case extract_and_validate_user_info(hello.payload) do
          {:ok, {type, {user, tenant_or_alias, db_name, search_path}}} ->
            app_name = normalize_app_name(hello.payload["application_name"])
            log_level = extract_log_level(hello)
            {:ok, {type, {user, tenant_or_alias, db_name, search_path}}, app_name, log_level}

          {:error, reason} ->
            {:error, {:invalid_user_info, reason}}
        end

      {:error, error} ->
        {:error, {:decode_error, error}}
    end
  end

  @doc """
  Extracts and validates user information from startup payload.
  """
  @spec extract_and_validate_user_info(map()) ::
          {:ok, {atom(), {String.t(), String.t(), String.t() | nil, String.t() | nil}}}
          | {:error, term()}
  def extract_and_validate_user_info(payload) do
    {type, {user, tenant_or_alias, db_name}} = HandlerHelpers.parse_user_info(payload)

    if Helpers.validate_name(user) and Helpers.validate_name(db_name) do
      search_path = payload["options"]["--search_path"]
      {:ok, {type, {user, tenant_or_alias, db_name, search_path}}}
    else
      {:error, {:invalid_format, {user, db_name}}}
    end
  end

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
    if tenant_feature_flags &&
         FeatureFlag.enabled?(tenant_feature_flags, "named_prepared_statements") do
      MessageStreamer.handle_packets(data.stream_state, bin)
    else
      {:ok, data.stream_state, bin}
    end
  end

  def process_client_packets(bin, _mode, data) do
    {:ok, data.stream_state, bin}
  end

  ## Protocol Utilities

  @doc """
  Normalizes application name from client connection.

  Returns sanitized string or default "Supavisor" for invalid names.
  """
  @spec normalize_app_name(any()) :: String.t()
  def normalize_app_name(name) when is_binary(name), do: name
  def normalize_app_name(nil), do: "Supavisor"

  def normalize_app_name(name) do
    Logger.debug("ClientHandler: Invalid application name #{inspect(name)}")
    "Supavisor"
  end

  @doc """
  Extracts log level from startup message options.

  Returns atom log level or nil if not specified or invalid.
  """
  @spec extract_log_level(map()) :: atom() | nil
  def extract_log_level(%{"payload" => %{"options" => options}}) do
    level = options["log_level"] && String.to_existing_atom(options["log_level"])

    if level in [:debug, :info, :notice, :warning, :error] do
      level
    else
      nil
    end
  end

  def extract_log_level(_), do: nil
end
