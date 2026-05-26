defmodule Supavisor.HttpSql do
  @moduledoc """
  Public facade for the HTTP /sql endpoint. Resolves a pooled Postgrex
  connection for the request's `(tenant, user, password_hash)` triple,
  runs the query (or batch), and returns the response body shaped per
  Neon's `/sql` wire format.

  Single-query path: `execute/2`.
  Batched-transaction path: `execute_batch/3`.

  All errors flow back through `Supavisor.HttpSql.ErrorMapper.to_neon_error/1`
  for consistent `{status, body}` mapping in the controller.
  """

  alias Supavisor.HttpSql.{
    ClientHandler,
    ResponseBuilder,
    Telemetry,
    Transaction
  }

  @type ctx :: %{
          required(:tenant_external_id) => String.t(),
          required(:user) => String.t(),
          required(:password) => String.t(),
          required(:database) => String.t() | nil,
          optional(:remote_ip) => term,
          optional(:request_id) => term
        }

  @type response_opts :: %{
          optional(:array_mode) => boolean
        }

  @type result_ok :: map
  @type result_err :: {:error, term}

  # ---------------------------------------------------------------------- API

  @doc """
  Execute a single query and return the Neon-shaped response body.

  `ctx` carries the pre-resolved tenant/user/password from `NeonAuth` plug.
  `sql` is the literal SQL with `$1, $2, ...` placeholders; `params` is the
  list of parameter values to bind.
  """
  @spec execute(ctx, String.t(), list, response_opts) ::
          {:ok, map} | result_err
  def execute(ctx, sql, params, opts \\ %{}) do
    timeout = request_timeout_ms()
    t0 = System.monotonic_time(:microsecond)

    case ClientHandler.run_query(ctx, sql, params, timeout: timeout) do
      {:ok, result} ->
        Telemetry.pool_checkout(
          System.monotonic_time(:microsecond) - t0,
          :hit,
          %{tenant: ctx.tenant_external_id, user: ctx.user}
        )

        with :ok <- check_row_cap(result) do
          {:ok, ResponseBuilder.build_single(result, opts)}
        end

      {:error, %Supavisor.Errors.MaxConnectionsError{}} = err ->
        Telemetry.max_clients_rejected(
          %{tenant: ctx.tenant_external_id, user: ctx.user},
          :max_clients
        )

        err

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Execute a batch of queries inside one server-side transaction with the
  given `Neon-Batch-*` options. Returns a Neon batch response (`results`
  key wraps per-query bodies).
  """
  @spec execute_batch(ctx, [%{sql: String.t(), params: list}], Transaction.batch_opts(),
          response_opts
        ) ::
          {:ok, map} | result_err
  def execute_batch(ctx, queries, batch_opts \\ %{}, opts \\ %{}) when is_list(queries) do
    timeout = request_timeout_ms()
    t0 = System.monotonic_time(:microsecond)

    with {:ok, txn_sql} <- Transaction.build(batch_opts),
         {:ok, results} <- ClientHandler.run_batch(ctx, txn_sql, queries, timeout: timeout) do
      Telemetry.pool_checkout(
        System.monotonic_time(:microsecond) - t0,
        :hit,
        %{tenant: ctx.tenant_external_id, user: ctx.user}
      )

      with :ok <- check_batch_row_cap(results) do
        {:ok, ResponseBuilder.build_batch(results, opts)}
      end
    else
      {:error, %Supavisor.Errors.MaxConnectionsError{}} = err ->
        Telemetry.max_clients_rejected(
          %{tenant: ctx.tenant_external_id, user: ctx.user},
          :max_clients
        )

        err

      {:error, _} = err ->
        err
    end
  end

  # ---------------------------------------------------------------- Internals

  defp check_row_cap(%{num_rows: n}) when is_integer(n) do
    cap = max_response_rows()
    if n > cap, do: {:error, {:row_limit_exceeded, cap}}, else: :ok
  end

  defp check_row_cap(_), do: :ok

  defp check_batch_row_cap(results) when is_list(results) do
    cap = max_response_rows()
    total = Enum.reduce(results, 0, fn r, acc -> acc + (r.num_rows || 0) end)
    if total > cap, do: {:error, {:row_limit_exceeded, cap}}, else: :ok
  end

  defp request_timeout_ms do
    Application.get_env(:supavisor, :http_sql, [])
    |> Keyword.get(:request_timeout_ms, 30_000)
  end

  defp max_response_rows do
    Application.get_env(:supavisor, :http_sql, [])
    |> Keyword.get(:max_response_rows, 10_000)
  end
end
