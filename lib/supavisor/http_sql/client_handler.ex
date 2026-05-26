defmodule Supavisor.HttpSql.ClientHandler do
  @moduledoc """
  Request-scoped Postgres client for the HTTP /sql endpoint.

  Unlike `Supavisor.ClientHandler` (gen_statem driven by a real TCP socket
  spawned by Ranch), this module is just a function that runs **in the Plug
  request process**. It reuses every other piece of Supavisor's pool
  machinery:

    * `Supavisor.start_dist/3` ensures the tenant's TenantSupervisor exists,
      locally or via RPC.
    * `Supavisor.subscribe/2` enforces the tenant's `max_clients` limit and
      counts this request as a subscriber for the lifetime of the query.
    * `:poolboy.checkout/3` pulls a `Supavisor.DbHandler` worker.
    * `DbHandler.checkout/5` hands the worker our `{:proc, self()}` "socket"
      so backend response bytes arrive as `{:db_bytes, _}` Erlang messages
      instead of being written into a TCP/SSL peer.

  Once checked out we send a single PG extended-query round-trip
  (`Parse + Bind + Describe(P) + Execute + Sync`) with text-format parameters
  and let `Supavisor.HttpSql.WireDecoder` turn the backend reply into a
  structured `%{columns, rows, command, num_rows}` map for the response
  builder. There is no `Postgrex.transaction` wrapper, no prepare round-trip,
  no second loopback hop, and no per-OID parameter coercion — exactly what
  we agreed with @v0idpwn for #152.

  ## Callback contract

  `DbHandler` calls `caller_module.db_status(caller, :ready_for_query)` after
  the upstream backend's `Z` packet. This module exposes that callback as
  `db_status/2`, which just forwards the signal as `send(pid, {:db_status,
  :ready_for_query})` to the request process's mailbox so the receive loop
  can unblock.
  """

  alias Supavisor.HandlerHelpers
  alias Supavisor.HttpSql.{Params, PgError, Wire, WireDecoder}
  alias Supavisor.Secrets.PasswordSecrets

  require Supavisor

  @type ctx :: %{
          required(:tenant_external_id) => String.t(),
          required(:user) => String.t(),
          required(:db_user) => String.t(),
          required(:password) => String.t(),
          required(:database) => String.t(),
          optional(:remote_ip) => term(),
          optional(:request_id) => term()
        }

  @type query_result :: %{
          columns: [%{name: String.t(), oid: pos_integer()}] | nil,
          rows: [[binary() | nil]],
          command: String.t() | nil,
          num_rows: non_neg_integer()
        }

  @type batch_query :: %{required(:sql) => String.t(), required(:params) => [term()]}

  @default_timeout 30_000

  # --------------------------------------------------------------------- API

  @doc """
  Execute one parameterised SQL statement and return its structured result.

  `params` is the list of parameter values as they came off the wire (JSON
  scalars). They are stringified into Postgres text format here — no Postgrex
  binary encoder is involved, which is what lets us avoid `ParamCoercer` for
  the new path.
  """
  @spec run_query(ctx(), String.t(), [term()], keyword()) ::
          {:ok, query_result()} | {:error, term()}
  def run_query(ctx, sql, params, opts \\ []) when is_binary(sql) and is_list(params) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    # DbHandler.checkout/5 process-links the calling process. Without
    # trap_exit, a DbHandler crash mid-query would kill the Plug task
    # before ErrorMapper could turn the failure into a 5xx response.
    Process.flag(:trap_exit, true)

    id = build_id(ctx)
    secrets = build_secrets(ctx)

    with {:ok, sup} <- Supavisor.start_dist(id, secrets, log_level: nil),
         {:ok, sub} <- subscribe(id, sup) do
      try do
        do_run_query(sub.workers, sql, params, timeout)
      after
        unsubscribe(sub.workers.manager)
        flush_db_mailbox()
      end
    end
  end

  defp do_run_query(workers, sql, params, timeout) do
    with {:ok, db_pid} <- pool_checkout(workers.pool, timeout),
         {:ok, upstream_sock} <- db_checkout(db_pid, timeout) do
      result =
        with :ok <- send_extended_query(upstream_sock, sql, Params.stringify_list(params)),
             {:ok, raw} <- recv_until_rfq(timeout, db_pid),
             {:ok, decoded} <- WireDecoder.parse_execute_response(raw) do
          {:ok, decoded}
        end

      maybe_return_worker(workers.pool, db_pid, result)
      result
    end
  end

  @doc """
  Execute a batch of queries inside a single server-side transaction.

  `txn_sql` is a `SET TRANSACTION ...` statement (or `nil`) produced by
  `Supavisor.HttpSql.Transaction.build/1` from the `Neon-Batch-*` request
  headers. The whole batch shares one Manager subscription and one DbHandler
  worker; the first error aborts and rolls back.
  """
  @spec run_batch(ctx(), String.t() | nil, [batch_query()], keyword()) ::
          {:ok, [query_result()]} | {:error, term()}
  def run_batch(ctx, txn_sql, queries, opts \\ []) when is_list(queries) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    # See `run_query/4` — trap_exit is required because DbHandler links us.
    Process.flag(:trap_exit, true)

    id = build_id(ctx)
    secrets = build_secrets(ctx)

    with {:ok, sup} <- Supavisor.start_dist(id, secrets, log_level: nil),
         {:ok, sub} <- subscribe(id, sup) do
      try do
        do_run_batch(sub.workers, txn_sql, queries, timeout)
      after
        unsubscribe(sub.workers.manager)
        flush_db_mailbox()
      end
    end
  end

  defp do_run_batch(workers, txn_sql, queries, timeout) do
    with {:ok, db_pid} <- pool_checkout(workers.pool, timeout),
         {:ok, upstream_sock} <- db_checkout(db_pid, timeout) do
      result = run_batch_body(upstream_sock, txn_sql, queries, timeout, db_pid)
      maybe_return_worker(workers.pool, db_pid, result)
      result
    end
  end

  @doc """
  Callback invoked by `Supavisor.DbHandler` when the backend's
  `ReadyForQuery` arrives. We do not actually need this for unblocking — the
  RFQ bytes themselves come through `{:db_bytes, _}` and the receive loop
  notices them — but DbHandler insists on calling something, so we accept it
  and discard.
  """
  @spec db_status(pid(), atom()) :: :ok
  def db_status(pid, status) when is_pid(pid) do
    send(pid, {:db_status, status})
    :ok
  end

  # ---------------------------------------------------------------- Internals

  defp build_id(ctx) do
    Supavisor.id(
      type: :single,
      tenant: ctx.tenant_external_id,
      user: ctx.db_user,
      mode: :transaction,
      db: ctx.database,
      search_path: nil
    )
  end

  defp build_secrets(ctx) do
    %PasswordSecrets{user: ctx.db_user, password: ctx.password}
  end

  # Subscribe this HTTP-request process to the tenant's pool Manager.
  #
  # If the TenantSupervisor (`sup`) lives on the local node we can use
  # `Supavisor.subscribe/1` directly. Otherwise we fetch the remote node's
  # workers via `:erpc.call` and subscribe through a raw GenServer.call —
  # `Manager.subscribe/2` has a `node(manager) == node()` guard for safety,
  # but the underlying GenServer.call works fine cross-node, and
  # `Process.monitor/1` (which Manager uses to clean up DOWN subscribers)
  # also monitors remote pids correctly.
  #
  # The TCP client_handler falls back to `:proxy` mode in this case because
  # it expects to write/read raw PG bytes against a peer socket. The HTTP
  # path doesn't have a peer socket to proxy to — backend bytes come back
  # as Erlang messages over node-to-node distribution, which works for any
  # node in the cluster.
  defp subscribe(id, sup) do
    if node(sup) == node() do
      Supavisor.subscribe(id)
    else
      subscribe_remote(node(sup), id)
    end
  end

  @doc false
  # Public-with-`@doc false` so tests can exercise the rescue/catch
  # branches without staging a real second-node deployment.
  #
  # `:erpc.call/4` raises `ErlangError` (or `:exit`) on every failure path
  # we care about — `{:erpc, :noconnection}` for unreachable nodes,
  # `{:erpc, :badarg}` for malformed node names, and `{:exception, e, _}`
  # for raises on the remote side. Catch the whole shape so the HTTP
  # request always gets a tagged error tuple instead of an uncaught
  # exception that would crash the Plug task and dump conn state.
  def subscribe_remote(pool_node, id) do
    case :erpc.call(pool_node, Supavisor, :get_local_workers, [id]) do
      {:ok, workers} ->
        case GenServer.call(workers.manager, {:subscribe, self()}) do
          {:ok, ps, idle_timeout} ->
            {:ok, %{workers: workers, ps: ps, idle_timeout: idle_timeout}}

          {:error, _} = err ->
            err
        end

      {:error, _} = err ->
        err

      other ->
        {:error, {:remote_workers_unexpected, other}}
    end
  rescue
    e -> {:error, {:remote_workers_unreachable, e}}
  catch
    :exit, reason -> {:error, {:remote_workers_unreachable, reason}}
  end

  defp pool_checkout(pool, timeout) do
    {:ok, :poolboy.checkout(pool, true, timeout)}
  catch
    :exit, {:timeout, _} -> {:error, :pool_checkout_timeout}
    :exit, reason -> {:error, {:pool_checkout_exit, reason}}
  end

  defp db_checkout(db_pid, timeout) do
    Supavisor.DbHandler.checkout(
      db_pid,
      {:proc, self()},
      self(),
      :transaction,
      timeout: timeout,
      caller_module: __MODULE__
    )
  end

  # Drive the whole batch over a single checked-out worker. BEGIN and
  # COMMIT/ROLLBACK are sent as simple Query messages; each user query is
  # an independent extended-query round-trip.
  defp run_batch_body(upstream_sock, txn_sql, queries, timeout, db_pid) do
    with :ok <- simple_query(upstream_sock, "BEGIN", timeout, db_pid),
         :ok <- maybe_simple_query(upstream_sock, txn_sql, timeout, db_pid),
         {:ok, results} <- run_batch_queries(upstream_sock, queries, timeout, db_pid) do
      case simple_query(upstream_sock, "COMMIT", timeout, db_pid) do
        :ok -> {:ok, results}
        {:error, _} = err -> err
      end
    else
      {:error, _} = err ->
        # Best-effort rollback. If the connection is gone, ROLLBACK will
        # fail too — that's fine, the connection's transaction will be
        # discarded by the backend on socket close.
        _ = simple_query(upstream_sock, "ROLLBACK", timeout, db_pid)
        err
    end
  end

  defp maybe_simple_query(_sock, nil, _timeout, _db_pid), do: :ok
  defp maybe_simple_query(sock, sql, timeout, db_pid), do: simple_query(sock, sql, timeout, db_pid)

  defp simple_query(upstream_sock, sql, timeout, db_pid) do
    with :ok <- HandlerHelpers.sock_send(upstream_sock, Wire.query(sql)),
         {:ok, raw} <- recv_until_rfq(timeout, db_pid),
         {:ok, _result} <- WireDecoder.parse_execute_response(raw) do
      :ok
    end
  end

  defp run_batch_queries(upstream_sock, queries, timeout, db_pid) do
    Enum.reduce_while(queries, {:ok, []}, fn %{sql: sql, params: params}, {:ok, acc} ->
      stringified = Params.stringify_list(params)

      with :ok <- send_extended_query(upstream_sock, sql, stringified),
           {:ok, raw} <- recv_until_rfq(timeout, db_pid),
           {:ok, result} <- WireDecoder.parse_execute_response(raw) do
        {:cont, {:ok, [result | acc]}}
      else
        {:error, _} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      {:error, _} = err -> err
    end
  end

  @doc false
  # Build and send Parse + Bind + Describe(P) + Execute + Sync over the upstream
  # socket in a single write. Exposed (with @doc false) for tests that exercise
  # the wire-format composition without booting a real DbHandler.
  @spec send_extended_query(Supavisor.sock(), String.t(), [Params.param()]) ::
          :ok | {:error, term()}
  def send_extended_query(upstream_sock, sql, params) do
    msg = [
      Wire.parse("", sql),
      Wire.bind("", "", params),
      Wire.describe(:portal, ""),
      Wire.execute("", 0),
      Wire.sync()
    ]

    HandlerHelpers.sock_send(upstream_sock, msg)
  end

  @doc false
  # Drain `{:db_bytes, _}` messages until we see ReadyForQuery in the
  # accumulated buffer. `{:db_status, _}` is signalling-only — it tells us
  # the backend's RFQ has fired, but the bytes containing RFQ still arrive
  # as `:db_bytes`, so we keep reading until the buffer contains them.
  #
  # `db_pid`, when provided, lets us pattern-match EXIT signals from that
  # specific worker. Other EXIT signals (e.g. Cowboy's :shutdown during
  # graceful node-stop, our linked supervisor going down) get classified
  # as `:shutdown_signal` rather than mis-labelled as a DbHandler crash.
  # The arity-1 form passes `nil` for back-compat with tests that drive
  # the loop with synthetic messages and don't have a real worker pid.
  #
  # Exposed (with @doc false) so tests can drive the receive loop with
  # synthetic backend messages without booting a real DbHandler.
  @spec recv_until_rfq(timeout(), pid() | nil) :: {:ok, binary()} | {:error, term()}
  def recv_until_rfq(timeout, db_pid \\ nil) do
    deadline = System.monotonic_time(:millisecond) + timeout
    recv_until_rfq(<<>>, deadline, db_pid)
  end

  defp recv_until_rfq(acc, deadline, db_pid) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {:db_bytes, bin} ->
        acc2 = acc <> bin

        if WireDecoder.ready_for_query?(acc2) do
          {:ok, acc2}
        else
          recv_until_rfq(acc2, deadline, db_pid)
        end

      {:db_status, _status} ->
        recv_until_rfq(acc, deadline, db_pid)

      {:EXIT, pid, reason} when pid == db_pid ->
        {:error, {:db_handler_exit, reason}}

      {:EXIT, _other, reason} ->
        # An EXIT from something other than our DbHandler worker — most
        # commonly Cowboy's :shutdown during graceful node stop, or a
        # supervisor cascading down. Don't blame DbHandler for it.
        {:error, {:shutdown_signal, reason}}
    after
      remaining ->
        {:error, :timeout}
    end
  end

  # In transaction mode DbHandler clears `client_sock` and goes :idle on
  # RFQ; poolboy then sees the worker as free again.
  defp return_worker(pool, db_pid) do
    :poolboy.checkin(pool, db_pid)
  catch
    :exit, _ -> :ok
  end

  # The DbHandler worker is only safe to return to the pool when we've
  # received a `ReadyForQuery` from the backend (so DbHandler is back in
  # `:idle` and `client_sock` is cleared). Two paths satisfy that:
  #
  #   * `{:ok, _}` — happy path, RFQ arrived.
  #   * `{:error, %PgError{}}` — backend returned ErrorResponse + RFQ;
  #     the protocol is back to idle even though our query failed.
  #
  # For every other failure (timeout, dropped connection, malformed
  # backend frames) we DON'T checkin — leave the worker in whatever
  # broken state it's in and let `Process.link` from DbHandler propagate
  # the EXIT so poolboy spawns a fresh worker.
  defp maybe_return_worker(pool, db_pid, {:ok, _}), do: return_worker(pool, db_pid)
  defp maybe_return_worker(pool, db_pid, {:error, %PgError{}}), do: return_worker(pool, db_pid)
  defp maybe_return_worker(_pool, _db_pid, _other), do: :ok

  # Best-effort: the Manager may already be dead (supervisor restart, or
  # we may be inside a graceful-shutdown cascade). The Manager's :DOWN
  # handler cleans up its own ETS entries; we just stop counting against
  # the live subscriber set early so warm-pool idle-shutdown is responsive.
  defp unsubscribe(manager) do
    Supavisor.Manager.unsubscribe(manager)
  catch
    :exit, _ -> :ok
  end

  @doc false
  # After we've returned the worker, more `:db_bytes` should not arrive,
  # but if the timeline overlapped (e.g. on error paths) we drain whatever
  # is left so subsequent requests handled by this same Plug process do
  # not see stale signal. Exposed (with @doc false) so tests can assert
  # mailbox cleanup directly.
  @spec flush_db_mailbox() :: :ok
  def flush_db_mailbox do
    receive do
      {:db_bytes, _} -> flush_db_mailbox()
      {:db_status, _} -> flush_db_mailbox()
    after
      0 -> :ok
    end
  end
end
