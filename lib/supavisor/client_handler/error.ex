defmodule Supavisor.ClientHandler.Error do
  @moduledoc """
  Error handling and message formatting for ClientHandler.
  """

  alias Supavisor.{HandlerHelpers, Protocol.Server}

  require Supavisor.Protocol.PreparedStatements, as: PreparedStatements
  require Logger

  @doc """
  Handles error by logging and sending appropriate error message to the client socket.

  Optional context parameter is used for generic errors to indicate where they occurred.
  """
  @spec maybe_log_and_send_error(term(), term(), term()) :: :ok
  def maybe_log_and_send_error(sock, error, context \\ nil) do
    error_actions = process(error, context)
    message = Map.fetch!(error_actions, :error)
    log_message = Map.get(error_actions, :log_message)
    send_ready_for_query = Map.get(error_actions, :send_ready_for_query, false)
    auth_error = Map.get(error_actions, :auth_error, false)

    if log_message do
      Logger.error("ClientHandler: #{log_message}", auth_error: auth_error)
    end

    if send_ready_for_query do
      HandlerHelpers.sock_send(sock, [message, Server.ready_for_query()])
    else
      HandlerHelpers.sock_send(sock, message)
    end
  end

  @spec process(term(), term()) :: map()
  defp process({:error, :max_prepared_statements}, _context) do
    message_text =
      "max prepared statements limit reached. Limit: #{PreparedStatements.client_limit()} per connection"

    %{
      error: Server.error_message("XX000", message_text),
      log_message: message_text
    }
  end

  defp process({:error, :prepared_statement_on_simple_query}, _context) do
    message_text =
      "Supavisor transaction mode only supports prepared statements using the Extended Query Protocol"

    %{
      error: Server.error_message("XX000", message_text),
      log_message: message_text,
      send_ready_for_query: true
    }
  end

  defp process({:error, :max_prepared_statements_memory}, _context) do
    limit_mb = PreparedStatements.client_memory_limit_bytes() / 1_000_000

    message_text =
      "max prepared statements memory limit reached. Limit: #{limit_mb}MB per connection"

    %{
      error: Server.error_message("XX000", message_text),
      log_message: message_text
    }
  end

  defp process({:error, :prepared_statement_not_found, name}, _context) do
    message_text = "prepared statement #{inspect(name)} does not exist"

    %{
      error: Server.error_message("26000", message_text),
      log_message: message_text
    }
  end

  defp process({:error, :duplicate_prepared_statement, name}, _context) do
    message_text = "prepared statement #{inspect(name)} already exists"

    %{
      error: Server.error_message("42P05", message_text),
      log_message: message_text
    }
  end

  defp process({:error, :ssl_required, user}, _context) do
    %{
      error: Server.error_message("XX000", "SSL connection is required"),
      log_message: "Tenant is not allowed to connect without SSL, user #{user}"
    }
  end

  defp process({:error, :address_not_allowed, addr}, _context) do
    message = "Address not in tenant allow_list: " <> inspect(addr)

    %{
      error: Server.error_message("XX000", message),
      log_message: message
    }
  end

  defp process({:error, :tenant_not_found}, _context) do
    %{
      error: Server.error_message("XX000", "Tenant or user not found"),
      log_message: "Tenant not found"
    }
  end

  defp process({:error, :tenant_not_found, reason, type, user, tenant_or_alias}, _context) do
    %{
      error: Server.error_message("XX000", "Tenant or user not found"),
      log_message: "User not found: #{inspect(reason)} #{inspect({type, user, tenant_or_alias})}",
      auth_error: true
    }
  end

  defp process({:error, :auth_error, :wrong_password, user}, _context) do
    %{
      error: Server.error_message("28P01", "password authentication failed for user \"#{user}\""),
      log_message: "Exchange error: password authentication failed for user \"#{user}\"",
      auth_error: true
    }
  end

  defp process({:error, :auth_error, :timeout, _user}, context) do
    %{
      error: Server.error_message("08006", "connection failure during authentication"),
      log_message:
        "Timeout while waiting for message in state #{auth_context_description(context)}"
    }
  end

  defp process({:error, :auth_error, {:unexpected_message, details}, _user}, context) do
    %{
      error: Server.error_message("08P01", "protocol violation during authentication"),
      log_message:
        "#{auth_context_description(context)} unexpected message during authentication: #{inspect(details)}"
    }
  end

  defp process({:error, :auth_error, {:decode_error, error}}, context) do
    auth_stage = auth_context_description(context)

    %{
      error: Server.error_message("08P01", "protocol violation during authentication"),
      log_message: "#{auth_stage} auth decode error: #{inspect(error)}"
    }
  end

  defp process({:error, :auth_error, {:unexpected_message, other}}, context) do
    auth_stage = auth_context_description(context)

    %{
      error: Server.error_message("08P01", "protocol violation during authentication"),
      log_message: "#{auth_stage} auth unexpected message: #{inspect(other)}"
    }
  end

  defp process({:error, :auth_error, :timeout}, context) do
    %{
      error: Server.error_message("08006", "connection failure during authentication"),
      log_message:
        "Timeout while waiting for message in state #{auth_context_description(context)}"
    }
  end

  defp process({:error, {:invalid_user_info, {:invalid_format, {user, db_name}}}}, _context) do
    %{
      error:
        Server.error_message(
          "XX000",
          "Authentication error, reason: \"Invalid format for user or db_name\""
        ),
      log_message: "Invalid format for user or db_name: #{inspect({user, db_name})}"
    }
  end

  defp process({:error, :auth_error, reason}, context) do
    message =
      "Authentication error, reason: #{inspect(reason)}, context: #{auth_context_description(context)}"

    %{
      error: Server.error_message("XX000", message),
      log_message: message
    }
  end

  defp process({:error, :max_clients_reached}, _context) do
    %{
      error: Server.error_message("XX000", "Max client connections reached"),
      log_message: "Max client connections reached"
    }
  end

  defp process({:error, :max_clients_reached_session}, _context) do
    message =
      "MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size"

    %{
      error: Server.error_message("XX000", message),
      log_message: message
    }
  end

  defp process({:error, :max_pools_reached}, _context) do
    %{
      error: Server.error_message("XX000", "Max pools count reached"),
      log_message: "Max pools count reached"
    }
  end

  defp process({:error, :db_handler_exited, pid, reason}, _context) do
    message =
      case reason do
        :db_termination -> "Connection to database closed. Check logs for more information"
        _ -> "DbHandler exited. Check logs for more information."
      end

    %{
      error: Server.error_message("XX000", message),
      log_message: "DbHandler #{inspect(pid)} exited #{inspect(reason)}"
    }
  end

  defp process({:error, :session_timeout}, _context) do
    message =
      "MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size"

    %{
      error: Server.error_message("XX000", message),
      log_message: message
    }
  end

  defp process({:error, :transaction_timeout}, _context) do
    message = "Unable to check out connection from the pool due to timeout"

    %{
      error: Server.error_message("XX000", message),
      log_message: message
    }
  end

  defp process({:error, :subscribe_retries_exhausted}, _context) do
    message = "Failed to subscribe to tenant after multiple retries. Terminating."

    %{
      error: Server.error_message("XX000", message),
      log_message: message
    }
  end

  defp process({:error, :circuit_breaker_open, operation, blocked_until}, _context) do
    explanation = Supavisor.CircuitBreaker.explanation(operation)
    message = "Circuit breaker open for operation: #{operation}, blocked until: #{blocked_until}"

    %{
      error: Server.error_message("XX000", "Circuit breaker open: #{explanation}"),
      log_message: message
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

  defp auth_context_description(:handshake), do: "Handshake"
  defp auth_context_description(:auth_md5_wait), do: "MD5"
  defp auth_context_description(:auth_password_wait), do: "PASSWORD"
  defp auth_context_description(:auth_scram_first_wait), do: "SCRAM first"
  defp auth_context_description(:auth_scram_final_wait), do: "SCRAM final"
  defp auth_context_description(_), do: "Unknown"
end
