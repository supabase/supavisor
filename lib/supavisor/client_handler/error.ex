defmodule Supavisor.ClientHandler.Error do
  @moduledoc """
  Error handling and message formatting for ClientHandler.
  """

  alias Supavisor.Protocol.Server

  require Supavisor.Protocol.PreparedStatements, as: PreparedStatements

  @doc """
  Converts error tuples to properly formatted PostgreSQL error messages.

  Returns {message, send_ready_for_query?} tuple.

  Optional context parameter is used for generic errors to indicate where they occurred.
  """
  @spec to_message(term(), term()) :: {binary(), boolean()}
  def to_message(error, context \\ nil)

  def to_message({:error, :max_prepared_statements}, _context) do
    message_text =
      "max prepared statements limit reached. Limit: #{PreparedStatements.client_limit()} per connection"

    {Server.error_message("XX000", message_text), false}
  end

  def to_message({:error, :prepared_statement_on_simple_query}, _context) do
    message_text =
      "Supavisor transaction mode only supports prepared statements using the Extended Query Protocol"

    {Server.error_message("XX000", message_text), true}
  end

  def to_message({:error, :max_prepared_statements_memory}, _context) do
    limit_mb = PreparedStatements.client_memory_limit_bytes() / 1_000_000

    message_text =
      "max prepared statements memory limit reached. Limit: #{limit_mb}MB per connection"

    {Server.error_message("XX000", message_text), false}
  end

  def to_message({:error, :prepared_statement_not_found, name}, _context) do
    message_text = "prepared statement #{inspect(name)} does not exist"
    {Server.error_message("26000", message_text), false}
  end

  def to_message({:error, :duplicate_prepared_statement, name}, _context) do
    {Server.error_message("42P05", "prepared statement #{inspect(name)} already exists"), false}
  end

  def to_message({:error, :ssl_required}, _context) do
    {Server.error_message("XX000", "SSL connection is required"), false}
  end

  def to_message({:error, :ssl_required, _user}, _context) do
    {Server.error_message("XX000", "SSL connection is required"), false}
  end

  def to_message({:error, :address_not_allowed, addr}, _context) do
    message = "Address not in tenant allow_list: " <> inspect(addr)
    {Server.error_message("XX000", message), false}
  end

  def to_message({:error, :tenant_not_found}, _context) do
    {Server.error_message("XX000", "Tenant or user not found"), false}
  end

  def to_message({:error, :tenant_not_found, _reason, _type, _user, _tenant_or_alias}, _context) do
    {Server.error_message("XX000", "Tenant or user not found"), false}
  end

  def to_message({:error, :auth_error, :wrong_password, user}, _context) do
    {Server.error_message("28P01", "password authentication failed for user \"#{user}\""), false}
  end

  def to_message({:error, :auth_error, {:timeout, _message}, _user}, _context) do
    {Server.error_message("08006", "connection failure during authentication"), false}
  end

  def to_message({:error, :auth_error, {:unexpected_message, _details}, _user}, _context) do
    {Server.error_message("08P01", "protocol violation during authentication"), false}
  end

  def to_message({:error, :auth_error, reason}, _context) do
    {Server.error_message("XX000", "Authentication error, reason: #{inspect(reason)}"), false}
  end

  def to_message({:error, :max_clients_reached}, _context) do
    {Server.error_message("XX000", "Max client connections reached"), false}
  end

  def to_message({:error, :max_pools_reached}, _context) do
    {Server.error_message("XX000", "Max pools count reached"), false}
  end

  def to_message({:error, :db_handler_exited}, _context) do
    {Server.error_message("XX000", "DbHandler exited"), false}
  end

  def to_message({:error, :db_handler_exited, _pid, _reason}, _context) do
    {Server.error_message("XX000", "DbHandler exited"), false}
  end

  def to_message({:error, :session_timeout}, _context) do
    message =
      "MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size"

    {Server.error_message("XX000", message), false}
  end

  def to_message({:error, :transaction_timeout}, _context) do
    {Server.error_message("XX000", "Unable to check out process from the pool due to timeout"),
     false}
  end

  def to_message(error, context) do
    message =
      case context do
        nil -> "Internal error: #{inspect(error)}"
        context -> "Internal error (#{context}): #{inspect(error)}"
      end

    {Server.error_message("XX000", message), false}
  end

  @doc """
  Determines if an error should be logged and returns the appropriate log message.

  Returns {:log, message} if the error should be logged, or :no_log if logging
  should be handled elsewhere or skipped.

  Optional context parameter is used for generic errors to indicate where they occurred.
  """
  @spec to_log_message(term(), term()) :: {:log, String.t()} | :no_log
  def to_log_message(error, context \\ nil)

  def to_log_message({:error, :max_prepared_statements}, _context) do
    {:log,
     "max prepared statements limit reached. Limit: #{PreparedStatements.client_limit()} per connection"}
  end

  def to_log_message({:error, :prepared_statement_on_simple_query}, _context) do
    {:log,
     "Supavisor transaction mode only supports prepared statements using the Extended Query Protocol"}
  end

  def to_log_message({:error, :max_prepared_statements_memory}, _context) do
    limit_mb = PreparedStatements.client_memory_limit_bytes() / 1_000_000
    {:log, "max prepared statements memory limit reached. Limit: #{limit_mb}MB per connection"}
  end

  def to_log_message({:error, :prepared_statement_not_found, name}, _context) do
    {:log, "prepared statement #{inspect(name)} does not exist"}
  end

  def to_log_message({:error, :duplicate_prepared_statement, name}, _context) do
    {:log, "prepared statement #{inspect(name)} already exists"}
  end

  def to_log_message({:error, :ssl_required}, _context) do
    {:log, "Tenant is not allowed to connect without SSL"}
  end

  def to_log_message({:error, :ssl_required, user}, _context) do
    {:log, "Tenant is not allowed to connect without SSL, user #{user}"}
  end

  def to_log_message({:error, :address_not_allowed, addr}, _context) do
    {:log, "Address not in tenant allow_list: " <> inspect(addr)}
  end

  def to_log_message({:error, :tenant_not_found}, _context) do
    {:log, "Tenant or user not found"}
  end

  def to_log_message({:error, :tenant_not_found, reason, type, user, tenant_or_alias}, _context) do
    {:log, "User not found: #{inspect(reason)} #{inspect({type, user, tenant_or_alias})}"}
  end

  # Auth error logging with context
  def to_log_message({:error, :auth_error, {:decode_error, error}}, :auth_md5_wait) do
    {:log, "MD5 auth decode error: #{inspect(error)}"}
  end

  def to_log_message({:error, :auth_error, {:unexpected_message, other}}, :auth_md5_wait) do
    {:log, "MD5 auth unexpected message: #{inspect(other)}"}
  end

  def to_log_message({:error, :auth_error, {:decode_error, error}}, :auth_scram_first_wait) do
    {:log, "SCRAM first auth decode error: #{inspect(error)}"}
  end

  def to_log_message({:error, :auth_error, {:unexpected_message, other}}, :auth_scram_first_wait) do
    {:log, "SCRAM first auth unexpected message: #{inspect(other)}"}
  end

  def to_log_message({:error, :auth_error, {:decode_error, error}}, :auth_scram_final_wait) do
    {:log, "SCRAM final auth decode error: #{inspect(error)}"}
  end

  def to_log_message({:error, :auth_error, {:unexpected_message, other}}, :auth_scram_final_wait) do
    {:log, "SCRAM final auth unexpected message: #{inspect(other)}"}
  end

  def to_log_message({:error, :auth_error, {:timeout, _}}, context) do
    case context do
      :auth_md5_wait -> {:log, "Timeout while waiting for MD5 password"}
      :auth_scram_first_wait -> {:log, "Timeout while waiting for first SCRAM message"}
      :auth_scram_final_wait -> {:log, "Timeout while waiting for final SCRAM message"}
      _ -> {:log, "Authentication timeout"}
    end
  end

  # Fallback for other auth errors
  def to_log_message({:error, :auth_error, _}, _context), do: :no_log
  def to_log_message({:error, :auth_error, _, _}, _context), do: :no_log
  def to_log_message({:error, :auth_error, _, _, _}, _context), do: :no_log

  def to_log_message({:error, :max_clients_reached}, _context) do
    {:log, "Max client connections reached"}
  end

  def to_log_message({:error, :max_pools_reached}, _context) do
    {:log, "Max pools count reached"}
  end

  def to_log_message({:error, :db_handler_exited}, _context) do
    {:log, "DbHandler exited"}
  end

  def to_log_message({:error, :db_handler_exited, pid, reason}, _context) do
    {:log, "DbHandler #{inspect(pid)} exited #{inspect(reason)}"}
  end

  def to_log_message({:error, :session_timeout}, _context) do
    {:log,
     "MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size"}
  end

  def to_log_message({:error, :transaction_timeout}, _context) do
    {:log, "Unable to check out process from the pool due to timeout"}
  end

  def to_log_message(error, context) do
    message =
      case context do
        nil -> "Internal error: #{inspect(error)}"
        context -> "Internal error (#{context}): #{inspect(error)}"
      end

    {:log, message}
  end
end
