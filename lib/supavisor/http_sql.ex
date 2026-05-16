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

  alias Supavisor.HttpSql.{ParamCoercer, PoolRegistry, ResponseBuilder, Telemetry, Transaction}

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
    with {:ok, pool_pid, _hit} <- checkout(ctx),
         {:ok, qr} <- run_query(pool_pid, sql, params, opts) do
      {:ok, ResponseBuilder.build_single(qr, opts)}
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
    with {:ok, txn_sql} <- Transaction.build(batch_opts),
         {:ok, pool_pid, _hit} <- checkout(ctx),
         {:ok, results} <- run_batch(pool_pid, txn_sql, queries, opts) do
      {:ok, ResponseBuilder.build_batch(results, opts)}
    end
  end

  # ---------------------------------------------------------------- Internals

  defp checkout(ctx) do
    t0 = System.monotonic_time(:microsecond)

    case PoolRegistry.checkout(ctx) do
      {:ok, pid, hit?} ->
        Telemetry.pool_checkout(
          System.monotonic_time(:microsecond) - t0,
          hit?,
          %{tenant: ctx.tenant_external_id, user: ctx.user}
        )

        {:ok, pid, hit?}

      {:error, _} = err ->
        err
    end
  end

  defp run_query(pool, sql, params, opts) do
    timeout = Map.get(opts, :timeout) || request_timeout_ms()

    Postgrex.transaction(
      pool,
      fn conn -> prepare_and_execute(conn, sql, params, timeout) end,
      timeout: timeout
    )
    |> case do
      {:ok, qr} -> {:ok, qr}
      {:error, %Postgrex.Error{}} = err -> err
      {:error, reason} -> {:error, reason}
    end
  rescue
    e in [ArgumentError, Postgrex.Error] -> {:error, e}
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
  end

  defp prepare_and_execute(conn, sql, params, timeout) do
    case Postgrex.prepare(conn, "", sql, timeout: timeout) do
      {:ok, %Postgrex.Query{param_oids: oids} = q} ->
        coerced = ParamCoercer.coerce_list(params, oids)

        case Postgrex.execute(conn, q, coerced, timeout: timeout) do
          {:ok, %Postgrex.Query{} = q2, %Postgrex.Result{} = r} ->
            :ok = maybe_enforce_row_cap(r)
            {q2, r}

          {:error, %Postgrex.Error{} = e} ->
            Postgrex.rollback(conn, e)
        end

      {:error, %Postgrex.Error{} = e} ->
        Postgrex.rollback(conn, e)
    end
  end

  defp run_batch(pool, txn_sql, queries, opts) do
    timeout = Map.get(opts, :timeout) || request_timeout_ms()

    Postgrex.transaction(
      pool,
      fn conn ->
        if txn_sql, do: Postgrex.query!(conn, txn_sql, [])

        Enum.map(queries, fn %{sql: sql, params: params} ->
          prepare_and_execute(conn, sql, params, timeout)
        end)
      end,
      timeout: timeout
    )
    |> case do
      {:ok, results} -> {:ok, results}
      {:error, %Postgrex.Error{}} = err -> err
      {:error, reason} -> {:error, reason}
    end
  rescue
    e in [ArgumentError, Postgrex.Error] -> {:error, e}
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
  end

  defp maybe_enforce_row_cap(%Postgrex.Result{num_rows: n}) when is_integer(n) do
    cap = max_response_rows()
    if n > cap, do: throw({:row_limit_exceeded, cap}), else: :ok
  end

  defp maybe_enforce_row_cap(_), do: :ok

  defp request_timeout_ms do
    Application.get_env(:supavisor, :http_sql, [])
    |> Keyword.get(:request_timeout_ms, 30_000)
  end

  defp max_response_rows do
    Application.get_env(:supavisor, :http_sql, [])
    |> Keyword.get(:max_response_rows, 10_000)
  end
end
