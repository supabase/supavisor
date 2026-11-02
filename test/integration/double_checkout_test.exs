defmodule Supavisor.Integration.DoubleCheckoutTest do
  # A backend must only ever be checked out to one client. In transaction mode a worker
  # can go back to poolboy two ways: the DbHandler checks itself in when released, and
  # poolboy reclaims it when the client it was given to goes down. A client that
  # disconnects right after its query triggers both, and if another client checks out
  # in between, the late checkin returns the worker while that client still holds it.
  use Supavisor.DataCase, async: false

  import Supavisor.Asserts

  require Supavisor

  alias Supavisor.DbHandler
  alias Supavisor.Support.ProtocolClient

  @moduletag :integration

  @clients 16
  @churn_ms 15_000
  @reply_timeout 5_000

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "double_checkout_#{System.unique_integer([:positive])}"

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
            "pool_size" => 9,
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

  # Forces the losing order: poolboy sees the client go down, hands the worker to B, and
  # only then does the DbHandler's checkin from the old client's release arrive.
  #
  # That needs poolboy to see the client's death while the DbHandler still has it linked,
  # which is only a brief window for a real client. So the poolboy checkout is held by a
  # stand-in, whose death poolboy sees, while the DbHandler's caller stays alive.
  test "a late checkin doesn't return a worker that another client holds", %{tenant: tenant} do
    sock = connect(tenant)
    :ok = :gen_tcp.send(sock, query("SELECT 1"))
    :ok = ProtocolClient.recv_until_ready_for_query(sock, "")
    pool = pool(tenant)
    assert_eventually(30, 100, fn -> checked_out(pool) == 0 end)

    {stand_in, worker, checkout_ref} = checkout(pool)
    client_a = checkout_db_handler(worker, checkout_ref)

    Process.exit(stand_in, :kill)
    assert_eventually(30, 100, fn -> checked_out(pool) == 0 end)

    assert {_client_b, ^worker, _} = checkout(pool)

    send(client_a, :release)
    assert_receive :released, 1_000
    assert_eventually(30, 100, fn -> elem(:sys.get_state(worker), 0) == :idle end)
    _ = :poolboy.status(pool)

    {_client_c, other_worker, _} = checkout(pool)

    assert other_worker != worker, "worker was checked out to two clients at once"
  end

  # The same race through the proxy. It depends on timing, so a pass doesn't prove its
  # absence, but it finds it within seconds at this load.
  @tag timeout: @churn_ms + 2 * @reply_timeout + 30_000
  test "clients that disconnect after each query only get their own results", %{tenant: tenant} do
    stop = :atomics.new(1, [])
    deadline = System.monotonic_time(:millisecond) + @churn_ms

    failures =
      1..@clients
      |> Enum.map(fn _ -> Task.async(fn -> churn(tenant, deadline, stop) end) end)
      |> Task.await_many(@churn_ms + 2 * @reply_timeout + 20_000)
      |> List.flatten()

    assert failures == []
  end

  ## Clients that connect, run one query and leave

  defp churn(tenant, deadline, stop) do
    if System.monotonic_time(:millisecond) >= deadline or :atomics.get(stop, 1) == 1 do
      []
    else
      case one_query(tenant) do
        :ok ->
          churn(tenant, deadline, stop)

        failure ->
          :atomics.put(stop, 1, 1)
          [failure]
      end
    end
  end

  defp one_query(tenant) do
    sock = connect(tenant)
    value = Integer.to_string(System.unique_integer([:positive]))
    :ok = :gen_tcp.send(sock, query("SELECT #{value}::bigint"))

    result =
      case recv_rows(sock, "") do
        {:ok, [^value]} -> :ok
        {:ok, rows} -> {:wrong_result, expected: value, got: rows}
        {:error, reason} -> {:no_reply, expected: value, reason: reason}
      end

    # Terminate and close right away, so the ClientHandler exits just after its release.
    _ = :gen_tcp.send(sock, <<?X, 4::32>>)
    :gen_tcp.close(sock)
    result
  end

  defp recv_rows(sock, buf) do
    with {:ok, more} <- :gen_tcp.recv(sock, 0, @reply_timeout) do
      {pkts, _rest} = Supavisor.Protocol.split_pkts(buf <> more)

      if Enum.any?(pkts, &match?(<<?Z, _::binary>>, &1)) do
        {:ok, for(<<?D, _::32, 1::16, len::32, col::binary-size(len)>> <- pkts, do: col)}
      else
        recv_rows(sock, buf <> more)
      end
    end
  end

  defp connect(tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)

    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    ProtocolClient.authenticate(sock, "#{db_conf[:username]}.#{tenant}", db_conf[:password])
    sock
  end

  defp query(sql), do: <<?Q, byte_size(sql) + 5::32, sql::binary, 0>>

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

  defp checked_out(pool) do
    {_state, _available, _overflow, checked_out} = :poolboy.status(pool)
    checked_out
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
end
