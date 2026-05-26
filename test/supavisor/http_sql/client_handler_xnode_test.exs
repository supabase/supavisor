defmodule Supavisor.HttpSql.ClientHandlerXnodeTest do
  @moduledoc """
  Tests for the cross-node tenant-pool path in
  `Supavisor.HttpSql.ClientHandler`.

  The TCP `Supavisor.ClientHandler` handles "pool lives on another node" by
  falling back to `:proxy` mode (raw TCP byte-pipe). The HTTP path can't
  proxy raw bytes — it must consume backend wire bytes and turn them into
  JSON. So when `start_dist/3` returns a remote supervisor pid, we route
  Manager subscribe + worker checkout through `:erpc` to that node.

  These tests cover the **error-handling** half of the dispatch (the happy
  path requires a real second BEAM node and is exercised by
  `:integration` cluster scaffolding in `cluster_pooling_test.exs`).
  """

  use ExUnit.Case, async: false

  require Supavisor

  alias Supavisor.HttpSql.ClientHandler

  defp test_id do
    Supavisor.id(
      type: :single,
      tenant: "ten",
      user: "u",
      mode: :transaction,
      db: "postgres",
      search_path: nil
    )
  end

  describe "subscribe_remote/2 — node unreachable / not-distributed paths" do
    test "non-existent remote node → {:remote_workers_unreachable, _}" do
      # The test node IS distributed (test_helper.exs starts it as
      # primary@127.0.0.1), so :erpc.call can attempt a real connection.
      # The target node doesn't exist — :erpc raises :exit with {:erpc,
      # :noconnection} which our `catch :exit, reason` clause wraps.
      result = ClientHandler.subscribe_remote(:"nonexistent_zzz@127.0.0.1", test_id())

      assert {:error, {:remote_workers_unreachable, _reason}} = result
    end

    test "remote get_local_workers raise propagates as unreachable" do
      # `:erpc.call/4` on a local call also raises if the target function
      # raises. We wrap any rescued exception as unreachable so the HTTP
      # request gets a clean 503-mappable tuple instead of crashing the
      # Plug task.
      #
      # In a real cluster the same code path is the one that catches
      # `{:erpc, :noconnection}` when the peer dies mid-call. Both
      # surfaces share the rescue.
      result = ClientHandler.subscribe_remote(node(), test_id())

      assert {:error, {:remote_workers_unreachable, _}} = result
    end
  end

  describe "subscribe_remote/2 — argument validation" do
    test "binary instead of atom node name surfaces as ArgumentError-wrapped error" do
      result = ClientHandler.subscribe_remote("not-an-atom", test_id())

      assert {:error, {:remote_workers_unreachable, _}} = result
    end
  end
end
