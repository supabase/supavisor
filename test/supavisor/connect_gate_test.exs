defmodule Supavisor.ConnectGateTest do
  use ExUnit.Case, async: true

  alias Supavisor.ConnectGate

  require Supavisor

  defmodule FakeManager do
    use GenServer

    def start_link({id, feature_flags}), do: GenServer.start_link(__MODULE__, {id, feature_flags})

    def init({id, feature_flags}) do
      Registry.register(Supavisor.Registry.Tenants, {:manager, id}, nil)
      {:ok, feature_flags}
    end

    def handle_call(:get_config, _from, feature_flags) do
      {:reply, %{tenant_feature_flags: feature_flags}, feature_flags}
    end
  end

  setup context do
    id =
      Supavisor.id(
        type: :single,
        tenant: "tenant_#{System.unique_integer([:positive])}",
        user: "user",
        mode: :transaction,
        db: "postgres"
      )

    feature_flags = Map.get(context, :feature_flags, %{"connect_gate" => true})
    start_supervised!({FakeManager, {id, feature_flags}})

    if Map.get(context, :start_gate, true), do: start_supervised!({ConnectGate, %{id: id}})

    {:ok, id: id}
  end

  # Spawns a process that acquires a lease and forwards gate messages to the
  # test process. Sending it `:release` releases the lease.
  defp spawn_acquirer(id) do
    test = self()

    pid =
      spawn(fn ->
        {:ok, lease} = ConnectGate.acquire(id)
        send(test, {:acquired, self()})
        acquirer_loop(test, lease)
      end)

    assert_receive {:acquired, ^pid}
    pid
  end

  defp acquirer_loop(test, {_gate, ref} = lease) do
    receive do
      {:connect_lease, ^ref} ->
        send(test, {:granted, self()})
        acquirer_loop(test, lease)

      {:DOWN, ^ref, :process, _, _} ->
        send(test, {:gate_down, self()})

      :release ->
        ConnectGate.release(lease)
        acquirer_loop(test, lease)
    end
  end

  @tag feature_flags: %{"connect_gate" => false}, start_gate: false
  test "doesn't start when the feature flag is disabled", %{id: id} do
    assert :ignore = ConnectGate.start_link(%{id: id})
    assert {:error, :not_running} = ConnectGate.acquire(id)
  end

  test "grants one lease at a time, in arrival order", %{id: id} do
    first = spawn_acquirer(id)
    second = spawn_acquirer(id)
    third = spawn_acquirer(id)

    assert_receive {:granted, ^first}
    refute_receive {:granted, _}, 100

    send(first, :release)
    assert_receive {:granted, ^second}
    refute_receive {:granted, _}, 100

    send(second, :release)
    assert_receive {:granted, ^third}
  end

  test "grants the next lease when the holder goes down", %{id: id} do
    first = spawn_acquirer(id)
    second = spawn_acquirer(id)
    assert_receive {:granted, ^first}

    Process.exit(first, :kill)
    assert_receive {:granted, ^second}
  end

  test "skips waiters that went down", %{id: id} do
    first = spawn_acquirer(id)
    second = spawn_acquirer(id)
    third = spawn_acquirer(id)
    assert_receive {:granted, ^first}

    Process.exit(second, :kill)
    send(first, :release)

    assert_receive {:granted, ^third}
    refute_receive {:granted, ^second}, 100
  end

  @tag timeout: 15_000
  test "grants the next lease when the lease expires, ignoring the late release", %{id: id} do
    first = spawn_acquirer(id)
    second = spawn_acquirer(id)
    third = spawn_acquirer(id)
    assert_receive {:granted, ^first}

    refute_receive {:granted, _}, 4_500
    assert_receive {:granted, ^second}, 1_000

    send(first, :release)
    refute_receive {:granted, _}, 100

    send(second, :release)
    assert_receive {:granted, ^third}
  end

  test "waiters get a DOWN when the gate goes down", %{id: id} do
    first = spawn_acquirer(id)
    second = spawn_acquirer(id)
    assert_receive {:granted, ^first}

    stop_supervised!(ConnectGate)
    assert_receive {:gate_down, ^second}
  end
end
