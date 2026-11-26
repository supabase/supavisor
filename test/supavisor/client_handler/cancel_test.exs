defmodule Supavisor.ClientHandler.CancelTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler
  alias Supavisor.ClientHandler.Cancel
  alias Supavisor.ClientHandler.Data

  require Supavisor.Protocol.Server, as: Server

  defp unique_key, do: {System.unique_integer([:positive]), System.unique_integer([:positive])}

  defp fake_db do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)

    meta = %{pid: 1234, key: 5678, host: ~c"127.0.0.1", port: port, ip_version: :inet}
    {:ok, _} = Registry.register(Supavisor.Registry.PoolPids, self(), meta)
    listen
  end

  defp accept_cancel(listen) do
    {:ok, db_sock} = :gen_tcp.accept(listen, 1_000)
    expected = Server.cancel_message(1234, 5678)
    assert {:ok, ^expected} = :gen_tcp.recv(db_sock, 16, 1_000)
    db_sock
  end

  describe "send_cancel_query_and_wait/3" do
    test "returns only after the owning handler replies" do
      {pid, key} = unique_key()
      :ok = Cancel.listen_cancel_query(pid, key)

      task = Task.async(fn -> Cancel.send_cancel_query_and_wait(pid, key) end)

      assert_receive :cancel_query
      refute Task.yield(task, 100)

      :ok = Cancel.reply_cancel_done({pid, key})
      assert Task.await(task) == :ok
    end

    test "gives up when no handler owns the key" do
      {pid, key} = unique_key()

      assert Cancel.send_cancel_query_and_wait(pid, key, 50) == {:error, :timeout}
    end
  end

  describe "maybe_forward_cancel_to_db/2" do
    test "returns only after the database closes the cancel connection" do
      listen = fake_db()
      data = %{tenant: "tenant", db_connection: {nil, self(), nil}}

      task = Task.async(fn -> Cancel.maybe_forward_cancel_to_db(:busy, data) end)

      db_sock = accept_cancel(listen)
      refute Task.yield(task, 100)

      :ok = :gen_tcp.close(db_sock)
      assert Task.await(task) == :ok
    end

    test "gives up on a database that never closes the cancel connection" do
      listen = fake_db()
      data = %{tenant: "tenant", db_connection: {nil, self(), nil}}

      # waits out Cancel's 1 s @upstream_timeout; only sock_close can close it here
      {micros, :ok} = :timer.tc(fn -> Cancel.maybe_forward_cancel_to_db(:busy, data) end)
      assert micros >= 1_000_000

      db_sock = accept_cancel(listen)
      assert :gen_tcp.recv(db_sock, 0, 1_000) == {:error, :closed}
    end
  end

  describe "ClientHandler :cancel_query" do
    test "an idle handler releases the cancel connection at once" do
      {pid, key} = unique_key()
      :ok = Cancel.listen_cancel_query(pid, key)
      waiter = Task.async(fn -> Cancel.send_cancel_query_and_wait(pid, key, 1_000) end)
      assert_receive :cancel_query

      data = %Data{cancel_key: {pid, key}}
      assert ClientHandler.handle_event(:info, :cancel_query, :idle, data) == :keep_state_and_data
      assert Task.await(waiter) == :ok
    end

    test "a busy handler releases the cancel connection after the database closed it" do
      {pid, key} = unique_key()
      listen = fake_db()
      :ok = Cancel.listen_cancel_query(pid, key)
      waiter = Task.async(fn -> Cancel.send_cancel_query_and_wait(pid, key, 1_000) end)
      assert_receive :cancel_query

      data = %Data{tenant: "tenant", db_connection: {nil, self(), nil}, cancel_key: {pid, key}}

      handler =
        Task.async(fn -> ClientHandler.handle_event(:info, :cancel_query, :busy, data) end)

      db_sock = accept_cancel(listen)
      refute Task.yield(waiter, 100)

      :ok = :gen_tcp.close(db_sock)
      assert Task.await(handler) == :keep_state_and_data
      assert Task.await(waiter) == :ok
    end

    test "a busy handler without a cancel key still forwards" do
      listen = fake_db()
      data = Map.delete(%Data{tenant: "tenant", db_connection: {nil, self(), nil}}, :cancel_key)

      handler =
        Task.async(fn -> ClientHandler.handle_event(:info, :cancel_query, :busy, data) end)

      db_sock = accept_cancel(listen)
      :ok = :gen_tcp.close(db_sock)
      assert Task.await(handler) == :keep_state_and_data
    end
  end

  describe "ClientHandler CancelRequest" do
    test "closes the cancel connection only after the owner's ack" do
      {pid, key} = unique_key()
      :ok = Cancel.listen_cancel_query(pid, key)
      msg = {:tcp, nil, Server.cancel_message(pid, key)}

      task = Task.async(fn -> ClientHandler.handle_event(:info, msg, :exchange, %Data{}) end)
      assert_receive :cancel_query
      refute Task.yield(task, 100)

      :ok = Cancel.reply_cancel_done({pid, key})
      assert Task.await(task) == {:stop, :normal}
    end
  end
end
