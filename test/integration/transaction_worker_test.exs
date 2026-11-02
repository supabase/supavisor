defmodule Supavisor.Integration.TransactionWorkerTest do
  # A transaction mode worker goes back to poolboy two ways: the DbHandler checks itself in
  # when released, and poolboy reclaims it when the client it was given to goes down. With
  # a pool of one worker, neither may free it while another client holds it, or leave a
  # client waiting for a response.
  use Supavisor.DataCase, async: false

  import Supavisor.Asserts

  require Supavisor

  alias Supavisor.DbHandler
  alias Supavisor.Support.ProtocolClient

  @moduletag :integration

  setup_all do
    Supavisor.Support.SSLHelper.setup_downstream_certs()
    :ok
  end

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "transaction_worker_#{System.unique_integer([:positive])}"

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

    # The pool starts with the first client.
    {:ok, _} = query(connect(:tcp, tenant), "SELECT 1")
    {:ok, tenant: tenant, pool: pool(tenant)}
  end

  # poolboy sees the client go down and hands the worker to B, and only then does the
  # DbHandler's checkin from the old client's release arrive. For a real client that's a
  # brief window, so the poolboy checkout is held by a stand-in, whose death poolboy sees,
  # while the DbHandler's caller stays alive.
  test "a late checkin doesn't free a worker another client holds", %{pool: pool} do
    {stand_in, worker, checkout_ref} = checkout(pool)
    client_a = checkout_db_handler(worker, checkout_ref)

    Process.exit(stand_in, :kill)
    assert_eventually(30, 100, fn -> elem(:poolboy.status(pool), 3) == 0 end)
    assert {_client_b, ^worker, _} = checkout(pool)

    send(client_a, :release)
    assert_receive :released, 1_000
    assert_eventually(30, 100, fn -> elem(:sys.get_state(worker), 0) == :idle end)
    _ = :poolboy.status(pool)

    assert :poolboy.checkout(pool, false) != worker, "worker checked out to two clients at once"
  end

  # The worker sends backend_synced before writing a response, so its ClientHandler can
  # release it, and ignore its exit, while the write is still going. With the client's
  # socket stalled, the worker blocks writing the response to a SELECT 1, which fits in one
  # read from the backend, after its release. The test kills it there.
  for transport <- [:tcp, :tls] do
    test "a worker killed writing a released client's response closes it, over #{transport}",
         %{tenant: tenant, pool: pool} do
      sock = connect(unquote(transport), tenant)
      {:ok, _} = query(sock, "SELECT 1")
      # The worker checks in after the client has its reply. Until then, it'd look like the
      # released worker below.
      assert_eventually(30, 100, fn -> elem(:poolboy.status(pool), 3) == 0 end)
      client_handler = client_handler_of(tenant, sock)
      resume = stall_writes(client_handler)

      :ok = ProtocolClient.sock_send(sock, :pgo_protocol.encode_query_message("SELECT 1"))
      worker = released_and_writing(pool, client_handler, 100)
      ref = Process.monitor(client_handler)
      worker_ref = Process.monitor(worker)
      Process.exit(worker, :kill)
      # The kill is a signal: resumed too early, the write could finish before it lands.
      assert_receive {:DOWN, ^worker_ref, _, _, :killed}, 1_000
      resume.()

      assert drain(sock) == {:error, :closed}
      assert_receive {:DOWN, ^ref, _, _, _}, 5_000
    end
  end

  # A send to a TCP port queues all of it and returns, and with the client not reading, the
  # port stays busy and the next send blocks. Over TLS, the ssl sender does the writing.
  defp stall_writes(client_handler) do
    case :sys.get_state(client_handler) do
      {_, %{sock: {:gen_tcp, port}}} ->
        :ok = :gen_tcp.send(port, :binary.copy(<<0>>, 32 * 1024 * 1024))
        fn -> :ok end

      {_, %{sock: {:ssl, {:sslsocket, _, [_receiver, sender]}}}} ->
        :erlang.suspend_process(sender)
        fn -> :erlang.resume_process(sender) end
    end
  end

  # Released, and not checked in yet, so still writing.
  defp released_and_writing(_pool, _client_handler, 0) do
    flunk("the worker didn't block writing a response its ClientHandler released")
  end

  defp released_and_writing(pool, client_handler, tries) do
    with {:idle, %{db_connection: nil}} <- :sys.get_state(client_handler),
         {_, _, _, 1} <- :poolboy.status(pool) do
      [{_, worker, _, _}] = :gen_server.call(pool, :get_all_workers)
      worker
    else
      _ ->
        Process.sleep(10)
        released_and_writing(pool, client_handler, tries - 1)
    end
  end

  # The ClientHandler serving `sock`, idle, matched by the client's port.
  defp client_handler_of(tenant, sock) do
    {:ok, {_, port}} = sockname(sock)

    [client_handler] =
      for pid <- Process.list(),
          {:dictionary, dict} <- [Process.info(pid, :dictionary)],
          {Supavisor.ClientHandler, _, _} <- [dict[:"$initial_call"]],
          {:idle, %{id: id, sock: client_sock}} when id != nil <- [:sys.get_state(pid)],
          Supavisor.id(id, :tenant) == tenant,
          {:ok, {_, ^port}} <- [peername(client_sock)],
          do: pid

    client_handler
  end

  defp sockname({:ssl, sock}), do: :ssl.sockname(sock)
  defp sockname(sock), do: :inet.sockname(sock)

  defp peername({:ssl, sock}), do: :ssl.peername(sock)
  defp peername({:gen_tcp, sock}), do: :inet.peername(sock)

  ## Pool

  # Checks out from a process that holds the worker until it's killed.
  defp checkout(pool) do
    test = self()

    pid =
      spawn(fn ->
        send(test, {:checked_out, self(), :poolboy.checkout_ref(pool, true, 5_000)})
        Process.sleep(:infinity)
      end)

    on_exit(fn -> Process.exit(pid, :kill) end)
    assert_receive {:checked_out, ^pid, {worker, checkout_ref}}, 6_000
    {pid, worker, checkout_ref}
  end

  # A client the DbHandler is checked out to, releasing it when told to.
  defp checkout_db_handler(worker, checkout_ref) do
    test = self()

    pid =
      spawn(fn ->
        {:ok, _db_sock} =
          DbHandler.checkout(worker, {:gen_tcp, nil}, self(), checkout_ref, :transaction)

        send(test, :db_checked_out)

        receive do
          :release ->
            DbHandler.release(worker, 0)
            send(test, :released)
        end

        Process.sleep(:infinity)
      end)

    on_exit(fn -> Process.exit(pid, :kill) end)
    assert_receive :db_checked_out, 5_000
    pid
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

  ## Client

  defp connect(transport, tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    sock = upgrade(transport, tcp)
    ProtocolClient.authenticate(sock, "#{db_conf[:username]}.#{tenant}", db_conf[:password])
    sock
  end

  defp upgrade(:tcp, tcp), do: tcp

  defp upgrade(:tls, tcp) do
    :ok = :gen_tcp.send(tcp, <<8::32, 1234::16, 5679::16>>)
    {:ok, "S"} = :gen_tcp.recv(tcp, 1, 5_000)
    {:ok, ssl} = :ssl.connect(tcp, [verify: :verify_none, active: false], 5_000)
    {:ssl, ssl}
  end

  # The single-column rows of a simple query.
  defp query(sock, sql) do
    :ok = ProtocolClient.sock_send(sock, :pgo_protocol.encode_query_message(sql))
    recv_rows(sock, "")
  end

  defp recv_rows(sock, buf) do
    with {:ok, more} <- ProtocolClient.sock_recv(sock, 5_000) do
      {pkts, _rest} = Supavisor.Protocol.split_pkts(buf <> more)

      cond do
        Enum.any?(pkts, &match?(<<?E, _::binary>>, &1)) ->
          {:error, {:error_response, pkts}}

        Enum.any?(pkts, &match?(<<?Z, _::binary>>, &1)) ->
          {:ok, for(<<?D, _::32, 1::16, len::32, col::binary-size(len)>> <- pkts, do: col)}

        true ->
          recv_rows(sock, buf <> more)
      end
    end
  end

  # Reads everything the client was sent. A hung client would time out here.
  defp drain(sock) do
    case ProtocolClient.sock_recv(sock, 5_000) do
      {:ok, _} -> drain(sock)
      {:error, _} = error -> error
    end
  end
end
