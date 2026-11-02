defmodule Supavisor.Integration.KilledWorkerTest do
  # A worker sends backend_synced before writing the response, so its ClientHandler can
  # release it, and stop caring about its exit, while the write is still going. A worker
  # killed there must not leave the client waiting on an open connection for the rest of a
  # response that will never come. The client stops reading until a worker blocks writing
  # a response its ClientHandler already released, and the test kills that worker.
  use Supavisor.DataCase, async: false

  require Supavisor

  alias Supavisor.Support.ProtocolClient

  @moduletag :integration

  @attempts 10

  # One read from the backend, so a worker blocked writing it has sent backend_synced.
  @query "SELECT repeat('x', 2000)"

  setup_all do
    Supavisor.Support.SSLHelper.setup_downstream_certs()
    :ok
  end

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "killed_worker_#{System.unique_integer([:positive])}"

    {:ok, _} =
      Supavisor.Tenants.create_tenant(%{
        db_host: db_conf[:hostname],
        db_port: db_conf[:port],
        db_database: db_conf[:database],
        default_parameter_status: %{},
        external_id: tenant,
        require_user: true,
        users: [
          %{
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 1,
            "max_clients" => 100,
            "mode_type" => "transaction"
          }
        ]
      })

    on_exit(fn ->
      Supavisor.stop(
        Supavisor.id(type: :single, tenant: tenant, user: db_conf[:username], mode: :transaction)
      )
    end)

    {:ok, tenant: tenant}
  end

  @tag timeout: 300_000
  test "over TCP, the client's connection closes", %{tenant: tenant} do
    attempt(tenant, 1)
  end

  # The ClientHandler's TLS sender is suspended, as one stuck on a slow client would be, so
  # the worker blocks writing the response to the next query. That one fits in a single
  # read from the backend, so the worker has sent backend_synced and been released.
  test "over TLS, the client's connection closes", %{tenant: tenant} do
    sock = connect(:tls, tenant)
    :ok = send_query(sock, "SELECT 1")
    {:ok, _} = drain_until_ready(sock, "")
    client_handler = client_handler_of(tenant)

    {_state, %{sock: {:ssl, {:sslsocket, _, [_receiver, sender]}}}} =
      :sys.get_state(client_handler)

    :erlang.suspend_process(sender)
    :ok = send_query(sock, "SELECT 1")
    worker = released_and_blocked(pool(tenant), client_handler, 100)

    ref = Process.monitor(client_handler)
    Process.exit(worker, :kill)
    :erlang.resume_process(sender)

    assert drain(sock) == {:error, :closed}
    assert_receive {:DOWN, ^ref, _, _, _}, 5_000
  end

  defp released_and_blocked(_pool, _client_handler, 0) do
    flunk("the worker didn't block writing a response its ClientHandler released")
  end

  defp released_and_blocked(pool, client_handler, tries) do
    worker = Enum.find(workers(pool), &blocked?/1)

    case :sys.get_state(client_handler) do
      {:idle, %{db_connection: nil}} when worker != nil ->
        worker

      _ ->
        Process.sleep(10)
        released_and_blocked(pool, client_handler, tries - 1)
    end
  end

  defp client_handler_of(tenant) do
    [client_handler] =
      for pid <- Process.list(),
          {:dictionary, dict} <- [Process.info(pid, :dictionary)],
          {Supavisor.ClientHandler, _, _} <- [dict[:"$initial_call"]],
          {:idle, %{id: id}} when id != nil <- [:sys.get_state(pid)],
          Supavisor.id(id, :tenant) == tenant,
          do: pid

    client_handler
  end

  defp attempt(_tenant, n) when n > @attempts do
    flunk("no worker blocked on a released client's write in #{@attempts} attempts")
  end

  defp attempt(tenant, n) do
    sock = connect(:tcp, tenant)
    :ok = send_query(sock, "SELECT 1")
    {:ok, _} = drain_until_ready(sock, "")

    worker = fill(sock, pool(tenant), 0)
    client_handler = client_handler(worker)
    {ch_state, ch_data} = :sys.get_state(client_handler)

    if ch_state == :idle and ch_data.db_connection == nil do
      ref = Process.monitor(client_handler)
      Process.exit(worker, :kill)

      assert drain(sock) == {:error, :closed}
      assert_receive {:DOWN, ^ref, _, _, _}, 5_000
    else
      # Blocked on a write before the final one, so the ClientHandler still holds it.
      :gen_tcp.close(sock)
      attempt(tenant, n + 1)
    end
  end

  # One query at a time, unread, until the worker blocks on a write.
  defp fill(sock, pool, sent) when sent < 100_000 do
    :ok = send_query(sock, @query)

    case wait_done_or_blocked(pool, 2_000) do
      :done -> fill(sock, pool, sent + 1)
      {:blocked, worker} -> worker
    end
  end

  defp wait_done_or_blocked(pool, left) when left > 0 do
    {_state, _avail, _overflow, checked_out} = :poolboy.status(pool)

    case Enum.find(workers(pool), &blocked?/1) do
      nil when checked_out == 0 ->
        :done

      nil ->
        Process.sleep(1)
        wait_done_or_blocked(pool, left - 1)

      worker ->
        Process.sleep(200)
        if blocked?(worker), do: {:blocked, worker}, else: wait_done_or_blocked(pool, left - 200)
    end
  end

  defp wait_done_or_blocked(pool, _left) do
    stacks = for w <- workers(pool), do: Process.info(w, [:status, :current_stacktrace])
    flunk("the worker neither finished nor blocked: #{inspect(stacks, limit: :infinity)}")
  end

  defp blocked?(worker) do
    case Process.info(worker, :current_stacktrace) do
      {:current_stacktrace, stack} ->
        Enum.any?(stack, fn {m, f, _, _} ->
          {m, f} in [
            {:erts_internal, :port_command},
            {:prim_inet, :send},
            {Supavisor.DbHandler, :chunk_send}
          ]
        end)

      nil ->
        false
    end
  end

  defp workers(pool) do
    for {_, pid, _, _} <- :gen_server.call(pool, :get_all_workers), is_pid(pid), do: pid
  end

  defp client_handler(worker) do
    {:links, links} = Process.info(worker, :links)

    [ch] =
      for pid <- links,
          is_pid(pid),
          {:dictionary, dict} <- [Process.info(pid, :dictionary)],
          {Supavisor.ClientHandler, _, _} <- [dict[:"$initial_call"]],
          do: pid

    ch
  end

  defp pool(tenant) do
    entries =
      Registry.select(Supavisor.Registry.Tenants, [{{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}])

    [pool] =
      for {{:pool, _, _, id}, pid} <- entries,
          Supavisor.id(id, :tenant) == tenant,
          do: pid

    pool
  end

  defp connect(:tcp, tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)
    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false, recbuf: 4096])
    ProtocolClient.authenticate(sock, "#{db_conf[:username]}.#{tenant}", db_conf[:password])
    sock
  end

  # ProtocolClient.authenticate, over TLS.
  defp connect(:tls, tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false, recbuf: 4096])
    :ok = :gen_tcp.send(tcp, <<8::32, 1234::16, 5679::16>>)
    {:ok, "S"} = :gen_tcp.recv(tcp, 1, 5_000)
    {:ok, ssl} = :ssl.connect(tcp, [verify: :verify_none, active: false], 5_000)
    sock = {:ssl, ssl}
    user = "#{db_conf[:username]}.#{tenant}"
    :ok = sock_send(sock, :pgo_protocol.encode_startup_message([{"user", user}]))
    {:ok, <<?R, _::32, 10::32, _::binary>>} = :ssl.recv(ssl, 0, 5_000)
    nonce = :pgo_scram.get_nonce(16)
    first = :pgo_scram.get_client_first(user, nonce)
    size = :erlang.iolist_size(first)

    :ok =
      sock_send(
        sock,
        :pgo_protocol.encode_scram_response_message(["SCRAM-SHA-256", 0, <<size::32>>, first])
      )

    {:ok, <<?R, _::32, 11::32, server_first::binary>>} = :ssl.recv(ssl, 0, 5_000)
    parts = :pgo_scram.parse_server_first(server_first, nonce)
    {final, _proof} = :pgo_scram.get_client_final(parts, nonce, user, db_conf[:password])
    :ok = sock_send(sock, :pgo_protocol.encode_scram_response_message(final))
    {:ok, _} = drain_until_ready(sock, "")
    sock
  end

  defp send_query(sock, sql), do: sock_send(sock, :pgo_protocol.encode_query_message(sql))

  defp sock_send({:ssl, ssl}, data), do: :ssl.send(ssl, data)
  defp sock_send(tcp, data), do: :gen_tcp.send(tcp, data)

  defp recv(sock, timeout) do
    case sock do
      {:ssl, ssl} -> :ssl.recv(ssl, 0, timeout)
      tcp -> :gen_tcp.recv(tcp, 0, timeout)
    end
  end

  defp drain_until_ready(sock, buf) do
    with {:ok, more} <- recv(sock, 5_000) do
      {pkts, rest} = Supavisor.Protocol.split_pkts(buf <> more)

      if Enum.any?(pkts, &match?(<<?Z, _::binary>>, &1)),
        do: {:ok, rest},
        else: drain_until_ready(sock, rest)
    end
  end

  # Reads everything the client was sent. A hung client would time out here.
  defp drain(sock) do
    case recv(sock, 5_000) do
      {:ok, _} -> drain(sock)
      {:error, _} = error -> error
    end
  end
end
