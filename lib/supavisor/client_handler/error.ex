defmodule Supavisor.ClientHandler.Error do
  @moduledoc """
  Error handling and message formatting for ClientHandler.
  """

  alias Supavisor.{HandlerHelpers, Monitoring.Telem, Protocol.Server}

  require Supavisor.Protocol.PreparedStatements, as: PreparedStatements
  require Logger

  @type context :: :handshake | :authenticated

  @doc """
  Handles error by logging, sending appropriate error message to the client socket,
  recording telemetry failure, and returning gen_statem termination action.

  Context values:
  - `:handshake` - Error during connection setup/auth (records client_join(:fail) telemetry, no ReadyForQuery)
  - `:authenticated` - Error after successful auth (no telemetry, sends ReadyForQuery)
  """
  @spec terminate_with_error(map(), Exception.t(), context()) ::
          :gen_statem.handle_event_result()
  def terminate_with_error(data, exception, context) do
    error_actions = process({:error, exception}, context)
    message = Map.get(error_actions, :error)
    log_message = Map.get(error_actions, :log_message)
    log_level = Map.get(error_actions, :log_level, :error)
    send_ready_for_query = Map.get(error_actions, :send_ready_for_query, false)
    auth_error = Map.get(error_actions, :auth_error, false)

    if log_message do
      Logger.log(log_level, "ClientHandler: #{log_message}", auth_error: auth_error)
    end

    # Only send message if one exists (some errors like socket closed can't send)
    if message do
      if send_ready_for_query do
        HandlerHelpers.sock_send(data.sock, [message, Server.ready_for_query()])
      else
        HandlerHelpers.sock_send(data.sock, message)
      end
    end

    # Record telemetry failure only during handshake phase
    if context == :handshake do
      Telem.client_join(:fail, data.id)
    end

    {:stop, :normal}
  end

  @spec process(term(), term()) :: map()
  defp process({:error, e}, stage) when is_exception(e) do
    error =
      case e.__struct__.postgres_error(e) do
        nil -> nil
        postgres_error -> Server.encode_error_message(postgres_error)
      end

    %{
      error: error,
      log_message: e.__struct__.log_message(e),
      log_level: e.__struct__.log_level(e),
      # It's very important for the protocol implementation that we send ReadyForQuery after
      # fatal errors in authenticated connections. In non authneticated connections, we should
      # close without sending ReadyForQuery
      send_ready_for_query: stage == :authenticated,
      auth_error: e.__struct__.is_auth_error(e)
    }
  end

  defp process(error, context) do
    message =
      case context do
        nil -> "Internal error: #{inspect(error)}"
        context -> "Internal error (#{context}): #{inspect(error)}"
      end

    %{
      error: Server.error_message("XX000", message),
      log_message: message
    }
  end
end
