defmodule Supavisor.HttpSql.FakeDbHandler do
  @moduledoc """
  Test double for `Supavisor.DbHandler` used by `ClientHandler` integration-style
  tests. Replicates only the slice of behaviour our HTTP /sql path depends on:

    * `:gen_statem.call({:checkout, sock, caller, caller_module}, _)` returns
      `{:ok, {:proc, self()}}` after stashing the client socket — so writes
      from the HTTP request process target this fake instead of a real
      upstream Postgres connection.

    * Incoming `{:db_bytes, _}` messages (the HTTP request writing its
      extended-query payload upstream) trigger the next entry from a
      pre-canned response script. Each entry is iodata sent back to the
      stored `client_sock` via `Supavisor.HandlerHelpers.sock_send/2` — which
      means the HTTP request receives `{:db_bytes, _}` messages exactly as it
      would from a real DbHandler.

  The fake speaks `gen_statem` semantics (not `GenServer`) because that's what
  the real `DbHandler.checkout/5` issues via `:gen_statem.call/3`. We use a
  hand-rolled `:gen_statem` so the call-shape matches verbatim.

  ## Usage

      script = [
        # Each element is the iodata that gets written back to the client
        # after one upstream write from the request. For most queries the
        # whole backend response arrives in a single chunk.
        IO.iodata_to_binary([
          parse_complete(),
          bind_complete(),
          row_description([{"n", 23}]),
          data_row(["42"]),
          command_complete("SELECT 1"),
          ready_for_query()
        ])
      ]

      {:ok, fake} = FakeDbHandler.start_link(script)

  Tests then drive `ClientHandler.send_extended_query({:proc, fake}, ...)`
  and `recv_until_rfq/1` to exercise the full conversation without a real
  Postgres backend.
  """

  @behaviour :gen_statem

  # ---------------------------------------------------------------------- API

  @spec start_link([iodata()]) :: {:ok, pid()}
  def start_link(script) when is_list(script) do
    :gen_statem.start_link(__MODULE__, %{script: script}, [])
  end

  @spec stop(pid()) :: :ok
  def stop(pid), do: :gen_statem.stop(pid)

  @doc """
  Returns the pid as a `{:proc, _}` socket that callers can write upstream
  PG-wire bytes to. The fake will respond with the next scripted chunk.
  """
  @spec upstream_sock(pid()) :: {:proc, pid()}
  def upstream_sock(pid), do: {:proc, pid}

  # --------------------------------------------------------- :gen_statem cbs

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(state) do
    Process.flag(:trap_exit, true)
    {:ok, :idle, Map.merge(state, %{client_sock: nil, caller: nil})}
  end

  @impl true
  # Real DbHandler.checkout uses this exact call shape; mirror it.
  def handle_event({:call, from}, {:checkout, sock, caller, _caller_module}, _state, data) do
    upstream = {:proc, self()}

    {:next_state, :busy, %{data | client_sock: sock, caller: caller},
     {:reply, from, {:ok, upstream}}}
  end

  # Bytes the HTTP request wrote "upstream" via sock_send({:proc, self()}, _).
  # Pop the next chunk from the script and emit it back to the client sock.
  def handle_event(:info, {:db_bytes, _request}, :busy, %{script: [resp | rest]} = data) do
    :ok = Supavisor.HandlerHelpers.sock_send(data.client_sock, resp)

    # Signal RFQ if the scripted chunk we just sent ends with the
    # ReadyForQuery packet, matching real DbHandler behaviour (it casts
    # `caller_module.db_status(caller, :ready_for_query)`).
    bin = IO.iodata_to_binary(resp)

    if String.ends_with?(bin, <<?Z, 5::32, ?I>>) or
         String.ends_with?(bin, <<?Z, 5::32, ?T>>) or
         String.ends_with?(bin, <<?Z, 5::32, ?E>>) do
      send(data.caller, {:db_status, :ready_for_query})
    end

    {:keep_state, %{data | script: rest}}
  end

  # No more scripted responses; ignore further upstream writes. Tests that
  # care about over-runs can inspect the fake's state via :gen_statem.call.
  def handle_event(:info, {:db_bytes, _request}, _state, data) do
    {:keep_state, data}
  end

  # Discard any other info — gen_statem boilerplate.
  def handle_event(:info, _msg, _state, _data), do: :keep_state_and_data

  @impl true
  def terminate(_reason, _state, _data), do: :ok
end
