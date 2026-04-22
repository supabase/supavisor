defmodule Supavisor.Integration.ConnectLimiterTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  @tenant "connect_limiter_tenant"
  @backend_port 23456

  defmodule SlowBackend do
    use GenServer

    def start_link(port) do
      GenServer.start_link(__MODULE__, port)
    end

    @impl true
    def init(port) do
      {:ok, listen_sock} = :gen_tcp.listen(port, [:binary, active: false, reuseaddr: true])
      send(self(), :accept)
      {:ok, %{listen_sock: listen_sock, connections: []}}
    end

    @impl true
    def handle_info(:accept, state) do
      case :gen_tcp.accept(state.listen_sock, 0) do
        {:ok, sock} ->
          send(self(), :accept)
          {:noreply, %{state | connections: [sock | state.connections]}}

        {:error, :timeout} ->
          Process.send_after(self(), :accept, 50)
          {:noreply, state}
      end
    end

    @impl true
    def terminate(_reason, state) do
      Enum.each(state.connections, &:gen_tcp.close/1)
      :gen_tcp.close(state.listen_sock)
    end
  end

  test "DbHandlers respect connect concurrency limit" do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_session)

    {:ok, _backend} = start_supervised({SlowBackend, @backend_port})

    # Start 15 Postgrex connections concurrently (pool has pool_size: 15)
    # They will complete client auth but DbHandlers will get stuck connecting to SlowBackend
    for _ <- 1..15 do
      Task.async(fn ->
        Postgrex.start_link(
          hostname: db_conf[:hostname],
          port: port,
          database: db_conf[:database],
          password: db_conf[:password],
          username: "#{db_conf[:username]}.#{@tenant}",
          connect_timeout: 15_000
        )
      end)
    end

    # Wait for DbHandlers to reach their states
    Process.sleep(500)

    id =
      Supavisor.id(
        type: :single,
        tenant: @tenant,
        user: db_conf[:username],
        mode: :session,
        db: db_conf[:database]
      )

    assert sup = Supavisor.get_global_sup(id)

    db_handler_pids = get_db_handler_pids(sup)
    assert length(db_handler_pids) == 15

    states =
      Enum.map(db_handler_pids, fn pid ->
        {state, _mode} = :gen_statem.call(pid, :get_state_and_mode)
        state
      end)

    connecting = Enum.count(states, &(&1 in [:connect, :authentication]))
    waiting = Enum.count(states, &(&1 == :waiting_for_connect_slot))

    assert connecting == 10
    assert waiting == 5
  end

  defp get_db_handler_pids(tenant_sup) do
    tenant_sup
    |> Supervisor.which_children()
    |> Enum.filter(&match?({:pool, _}, elem(&1, 0)))
    |> Enum.flat_map(fn {_id, pool_pid, _type, _modules} ->
      pool_pid
      |> Process.info()
      |> Kernel.get_in([:links])
      |> Enum.find(&poolboy_supervisor?/1)
      |> case do
        nil -> []
        poolboy_sup -> Supervisor.which_children(poolboy_sup)
      end
      |> Enum.filter(&is_pid(elem(&1, 1)))
      |> Enum.map(&elem(&1, 1))
    end)
  end

  defp poolboy_supervisor?(pid) do
    case Process.info(pid)[:dictionary][:"$initial_call"] do
      {:supervisor, :poolboy_sup, _} -> true
      _ -> false
    end
  end
end
