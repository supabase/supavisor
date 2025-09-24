defmodule Supavisor.ClientHandler.Error do
  @moduledoc """
  Error handling and message formatting for ClientHandler.
  """

  alias Supavisor.{HandlerHelpers, Protocol.Server}

  require Supavisor.Protocol.PreparedStatements, as: PreparedStatements

  @type error_response :: %{
          error: binary(),
          log_message: String.t() | nil,
          send_ready_for_query: boolean()
        }

  @doc """
  Handles error by logging and sending appropriate error message to the client socket.

  Optional context parameter is used for generic errors to indicate where they occurred.
  """
  @spec maybe_log_and_send_error(term(), term(), term()) :: :ok
  def maybe_log_and_send_error(sock, error, context \\ nil) do
    %{error: message, log_message: log_message, send_ready_for_query: send_ready_for_query} =
      process(error, context)

    if log_message do
      require Logger
      Logger.error("ClientHandler: #{log_message}")
    end

    if send_ready_for_query do
      HandlerHelpers.sock_send(sock, [message, Server.ready_for_query()])
    else
      HandlerHelpers.sock_send(sock, message)
    end
  end

  @spec process(term(), term()) :: error_response()
  defp process({:error, :max_prepared_statements}, _context) do
    message_text =
      "max prepared statements limit reached. Limit: #{PreparedStatements.client_limit()} per connection"

    %{
      error: Server.error_message("XX000", message_text),
      log_message: message_text,
      send_ready_for_query: false
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
      log_message: message_text,
      send_ready_for_query: false
    }
  end

  defp process({:error, :prepared_statement_not_found, name}, _context) do
    message_text = "prepared statement #{inspect(name)} does not exist"

    %{
      error: Server.error_message("26000", message_text),
      log_message: message_text,
      send_ready_for_query: false
    }
  end

  defp process({:error, :duplicate_prepared_statement, name}, _context) do
    message_text = "prepared statement #{inspect(name)} already exists"

    %{
      error: Server.error_message("42P05", message_text),
      log_message: message_text,
      send_ready_for_query: false
    }
  end

  defp process({:error, :ssl_required, user}, _context) do
    %{
      error: Server.error_message("XX000", "SSL connection is required"),
      log_message: "Tenant is not allowed to connect without SSL, user #{user}",
      send_ready_for_query: false
    }
  end

  defp process({:error, :address_not_allowed, addr}, _context) do
    message = "Address not in tenant allow_list: " <> inspect(addr)

    %{
      error: Server.error_message("XX000", message),
      log_message: message,
      send_ready_for_query: false
    }
  end

  defp process({:error, :tenant_not_found}, _context) do
    %{
      error: Server.error_message("XX000", "Tenant or user not found"),
      log_message: "Tenant not found",
      send_ready_for_query: false
    }
  end

  defp process({:error, :tenant_not_found, reason, type, user, tenant_or_alias}, _context) do
    %{
      error: Server.error_message("XX000", "Tenant or user not found"),
      log_message: "User not found: #{inspect(reason)} #{inspect({type, user, tenant_or_alias})}",
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, :wrong_password, user}, _context) do
    %{
      error: Server.error_message("28P01", "password authentication failed for user \"#{user}\""),
      log_message: nil,
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, {:timeout, _message}, _user}, _context) do
    %{
      error: Server.error_message("08006", "connection failure during authentication"),
      log_message: nil,
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, {:unexpected_message, _details}, _user}, _context) do
    %{
      error: Server.error_message("08P01", "protocol violation during authentication"),
      log_message: nil,
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, {:decode_error, error}}, context) do
    auth_stage = auth_context_description(context)

    %{
      error: Server.error_message("08P01", "protocol violation during authentication"),
      log_message: "#{auth_stage} auth decode error: #{inspect(error)}",
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, {:unexpected_message, other}}, context) do
    auth_stage = auth_context_description(context)

    %{
      error: Server.error_message("08P01", "protocol violation during authentication"),
      log_message: "#{auth_stage} auth unexpected message: #{inspect(other)}",
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, {:timeout, _}}, context) do
    log_message =
      case context do
        :auth_md5_wait -> "Timeout while waiting for MD5 password"
        :auth_scram_first_wait -> "Timeout while waiting for first SCRAM message"
        :auth_scram_final_wait -> "Timeout while waiting for final SCRAM message"
        _ -> "Authentication timeout"
      end

    %{
      error: Server.error_message("08006", "connection failure during authentication"),
      log_message: log_message,
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, :invalid_user_format}, _context) do
    %{
      error:
        Server.error_message(
          "XX000",
          "Authentication error, reason: \"Invalid format for user or db_name\""
        ),
      log_message: "Invalid format for user or db_name",
      send_ready_for_query: false
    }
  end

  defp process({:error, :auth_error, reason}, _context) do
    %{
      error: Server.error_message("XX000", "Authentication error, reason: #{inspect(reason)}"),
      log_message: nil,
      send_ready_for_query: false
    }
  end

  defp process({:error, :max_clients_reached}, _context) do
    %{
      error: Server.error_message("XX000", "Max client connections reached"),
      log_message: "Max client connections reached",
      send_ready_for_query: false
    }
  end

  defp process({:error, :max_pools_reached}, _context) do
    %{
      error: Server.error_message("XX000", "Max pools count reached"),
      log_message: "Max pools count reached",
      send_ready_for_query: false
    }
  end

  defp process({:error, :db_handler_exited, pid, reason}, _context) do
    %{
      error: Server.error_message("XX000", "DbHandler exited"),
      log_message: "DbHandler #{inspect(pid)} exited #{inspect(reason)}",
      send_ready_for_query: false
    }
  end

  defp process({:error, :session_timeout}, _context) do
    message =
      "MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size"

    %{
      error: Server.error_message("XX000", message),
      log_message: message,
      send_ready_for_query: false
    }
  end

  defp process({:error, :transaction_timeout}, _context) do
    message = "Unable to check out process from the pool due to timeout"

    %{
      error: Server.error_message("XX000", message),
      log_message: message,
      send_ready_for_query: false
    }
  end

  defp process({:error, :subscribe_retries_exhausted}, _context) do
    message = "Failed to subscribe to tenant after multiple retries. Terminating."

    %{
      error: Server.error_message("XX000", message),
      log_message: message,
      send_ready_for_query: false
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
      log_message: message,
      send_ready_for_query: false
    }
  end

  defp auth_context_description(:auth_md5_wait), do: "MD5"
  defp auth_context_description(:auth_scram_first_wait), do: "SCRAM first"
  defp auth_context_description(:auth_scram_final_wait), do: "SCRAM final"
  defp auth_context_description(_), do: "Unknown"
end
