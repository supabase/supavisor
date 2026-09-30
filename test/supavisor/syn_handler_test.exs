defmodule Supavisor.SynHandlerTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  import Supavisor.Support.ClientAuthenticationHelpers, only: [seed_cache: 2]
  require Logger
  require Supavisor
  alias Ecto.Adapters.SQL.Sandbox
  alias Supavisor.ClientAuthentication
  alias Supavisor.Support.Cluster
  alias Supavisor.SynHandler

  @id Supavisor.id(
        type: :single,
        tenant: "syn_tenant",
        user: "postgres",
        mode: :session,
        db: "postgres"
      )

  @id_local_wins Supavisor.id(
                   type: :single,
                   tenant: "syn_tenant_local_wins",
                   user: "postgres",
                   mode: :session,
                   db: "postgres"
                 )

  @tag cluster: true
  test "resolving conflict" do
    {:ok, peer, node2} = Cluster.start_node_unclustered(:peer.random_name())

    secret = %Supavisor.Secrets.PasswordSecrets{
      user: "postgres",
      password: "postgres"
    }

    {:ok, pid2} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [@id, secret])
    assert :peer.call(peer, Supavisor, :get_global_sup, [@id]) == pid2
    assert node(pid2) == node2

    assert nil == Supavisor.get_global_sup(@id)
    {:ok, pid1} = Supavisor.start(@id, secret)
    assert pid1 == Supavisor.get_global_sup(@id)
    assert node(pid1) == node()

    log =
      capture_log(fn ->
        true = Node.connect(node2)
        Process.sleep(500)
      end)

    assert log =~ "SynHandler: resolving"
    assert log =~ ~s(tenant: "syn_tenant")
    assert log =~ "SynHandler: Resolving"
    assert log =~ "conflict, stop local pid"
    assert log =~ "project=syn_tenant"
    assert log =~ "user=postgres"
    assert log =~ "mode=session"

    assert pid2 == Supavisor.get_global_sup(@id)
    assert node(pid2) == node2
  end

  @tag cluster: true
  test "resolving conflict, local pid wins" do
    {:ok, peer, node2} = Cluster.start_node_unclustered(:peer.random_name())

    secret = %Supavisor.Secrets.PasswordSecrets{
      user: "postgres",
      password: "postgres"
    }

    # Register the local pid first so it gets the earlier timestamp, making
    # it the pid that's kept and forcing the remote (peer) pid to be stopped.
    assert nil == Supavisor.get_global_sup(@id_local_wins)
    {:ok, pid_local} = Supavisor.start(@id_local_wins, secret)
    assert pid_local == Supavisor.get_global_sup(@id_local_wins)
    assert node(pid_local) == node()

    {:ok, pid_remote} =
      :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [@id_local_wins, secret])

    assert :peer.call(peer, Supavisor, :get_global_sup, [@id_local_wins]) == pid_remote
    assert node(pid_remote) == node2

    log =
      capture_log(fn ->
        true = Node.connect(node2)
        Process.sleep(500)
      end)

    assert log =~ "SynHandler: resolving"
    assert log =~ ~s(tenant: "syn_tenant_local_wins")
    assert log =~ "SynHandler: Resolving"
    assert log =~ "conflict, remote pid"
    assert log =~ "project=syn_tenant_local_wins"
    assert log =~ "user=postgres"
    assert log =~ "mode=session"

    assert pid_local == Supavisor.get_global_sup(@id_local_wins)
    assert node(pid_local) == node()
  end

  defp build_id(tenant, user, opts \\ []) do
    Supavisor.id(
      type: :single,
      tenant: tenant,
      user: user,
      mode: opts[:mode] || :transaction,
      db: opts[:db] || "postgres",
      search_path: nil
    )
  end

  defp fake_pid do
    spawn_link(fn -> Process.sleep(:infinity) end)
  end

  describe "on_process_registered/5" do
    test "joins the pool pid to the :tenants pg group for {tenant, user}" do
      tenant = "syn_handler_unit_test_#{System.unique_integer([:positive])}"
      user = "user1"
      id = build_id(tenant, user)
      pid = fake_pid()

      assert [] == Supavisor.tenant_pools(tenant, user)

      SynHandler.on_process_registered(:tenants, id, pid, nil, nil)

      assert [pid] == Supavisor.tenant_pools(tenant, user)
    end
  end

  describe "on_process_unregistered/5" do
    test "invalidates the local cache when no sibling pool remains for {tenant, user}" do
      tenant = "syn_handler_unit_test_#{System.unique_integer([:positive])}"
      user = "user1"
      id = build_id(tenant, user)
      seed_cache(tenant, user)

      log =
        capture_log(fn ->
          SynHandler.on_process_unregistered(:tenants, id, self(), nil, :shutdown)
        end)

      assert log =~ "invalidated client authentication"
      assert log =~ "project=#{tenant}"
      assert log =~ "user=#{user}"

      assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)
    end

    test "does not invalidate when a sibling pool is still joined for {tenant, user}" do
      tenant = "syn_handler_unit_test_#{System.unique_integer([:positive])}"
      user = "user1"
      id = build_id(tenant, user, mode: :transaction, db: "postgres")

      Supavisor.join_tenant_pool(tenant, user, fake_pid())
      seed_cache(tenant, user)

      SynHandler.on_process_unregistered(:tenants, id, self(), nil, :shutdown)

      assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
    end

    test "invalidates when the only other registered pool belongs to a different user on the same tenant" do
      tenant = "syn_handler_unit_test_#{System.unique_integer([:positive])}"
      user = "user1"
      other_user = "user2"
      id = build_id(tenant, user)

      Supavisor.join_tenant_pool(tenant, other_user, fake_pid())
      seed_cache(tenant, user)

      SynHandler.on_process_unregistered(:tenants, id, self(), nil, :shutdown)

      assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)
    end

    test "invalidates even if the unregistering pid is still a residual member of its own pg group" do
      # :syn's registry (keyed by `id`) and its pg group (keyed by {tenant, user}) are
      # monitored by two independent :syn processes. When a pool dies, the registry's
      # callback can run before the pg group has processed its own DOWN for the same
      # pid, so the dying pid can still show up as a "member" of its own group here.
      tenant = "syn_handler_unit_test_#{System.unique_integer([:positive])}"
      user = "user1"
      id = build_id(tenant, user)

      Supavisor.join_tenant_pool(tenant, user, self())
      seed_cache(tenant, user)

      SynHandler.on_process_unregistered(:tenants, id, self(), nil, :shutdown)

      assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)
    end

    test "does not invalidate if fails to check liveness of a remote pool" do
      tenant = "syn_handler_unit_test_#{System.unique_integer([:positive])}"
      user = "user1"
      id = build_id(tenant, user)

      Supavisor.join_tenant_pool(tenant, user, self())
      Supavisor.join_tenant_pool(tenant, user, fake_pid())
      seed_cache(tenant, user)

      log =
        capture_log(fn ->
          SynHandler.on_process_unregistered(:tenants, id, self(), nil, :test_rpc_failure)
        end)

      assert log =~ "Couldn't check liveness"
      assert log =~ "assuming alive"

      assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
    end
  end

  setup tags do
    pid = Sandbox.start_owner!(Supavisor.Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end
end
