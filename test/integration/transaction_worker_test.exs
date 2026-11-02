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
    :ok = query(connect(tenant), "SELECT 1")
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
  # release it, and ignore its exit, while the write is still going. Killed there, the
  # worker must take the client's connection down, or the client waits forever.
  #
  # A send to a TCP port queues all of it and returns, so queueing a lot on the
  # ClientHandler's socket, with the client not reading, leaves the port busy. The worker
  # then blocks writing the response to a SELECT 1, which fits in one read from the backend,
  # after its release and before the response is queued.
  test "a worker killed writing a released client's response closes it", %{
    tenant: tenant,
    pool: pool
  } do
    sock = connect(tenant)
    :ok = query(sock, "SELECT 1")
    client_handler = client_handler_of(tenant, sock)
    {_, %{sock: {:gen_tcp, client_port}}} = :sys.get_state(client_handler)
    :ok = :gen_tcp.send(client_port, :binary.copy(<<0>>, 32 * 1024 * 1024))

    :ok = :gen_tcp.send(sock, :pgo_protocol.encode_query_message("SELECT 1"))
    worker = blocked_after_release(pool, client_handler, 100)
    client_handler_ref = Process.monitor(client_handler)
    worker_ref = Process.monitor(worker)
    Process.exit(worker, :kill)
    assert_receive {:DOWN, ^worker_ref, _, _, :killed}, 1_000

    assert drain(sock) == {:error, :closed}
    assert_receive {:DOWN, ^client_handler_ref, _, _, _}, 5_000
  end

  # A worker blocked inside its write to the client, with the ClientHandler idle, so it
  # sent backend_synced and was released.
  defp blocked_after_release(_pool, _client_handler, 0) do
    flunk("no worker blocked writing a response its ClientHandler released")
  end

  defp blocked_after_release(pool, client_handler, tries) do
    worker = Enum.find(workers(pool), &writing?/1)

    case :sys.get_state(client_handler) do
      {:idle, %{db_connection: nil}} when worker != nil ->
        worker

      _ ->
        Process.sleep(10)
        blocked_after_release(pool, client_handler, tries - 1)
    end
  end

  defp writing?(worker) do
    case Process.info(worker, :current_stacktrace) do
      {:current_stacktrace, stack} -> Enum.any?(stack, &match?({:prim_inet, :send, _, _}, &1))
      nil -> false
    end
  end

  defp workers(pool) do
    for {_, pid, _, _} <- :gen_server.call(pool, :get_all_workers), is_pid(pid), do: pid
  end

  # The ClientHandler serving `sock`, idle, matched by the client's port.
  defp client_handler_of(tenant, sock) do
    {:ok, {_, port}} = :inet.sockname(sock)

    [client_handler] =
      for pid <- Process.list(),
          {:dictionary, dict} <- [Process.info(pid, :dictionary)],
          {Supavisor.ClientHandler, _, _} <- [dict[:"$initial_call"]],
          {:idle, %{id: id, sock: client_sock}} when id != nil <- [:sys.get_state(pid)],
          Supavisor.id(id, :tenant) == tenant,
          {:gen_tcp, client_port} <- [client_sock],
          {:ok, {_, ^port}} <- [:inet.peername(client_port)],
          do: pid

    client_handler
  end

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

  defp connect(tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)
    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    ProtocolClient.authenticate(sock, "#{db_conf[:username]}.#{tenant}", db_conf[:password])
    sock
  end

  defp query(sock, sql) do
    :ok = :gen_tcp.send(sock, :pgo_protocol.encode_query_message(sql))
    ProtocolClient.recv_until_ready_for_query(sock, "")
  end

  # Reads everything the client was sent. A hung client would time out here.
  defp drain(sock) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, _} -> drain(sock)
      {:error, _} = error -> error
    end
  end
end
