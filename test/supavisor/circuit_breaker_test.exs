defmodule Supavisor.CircuitBreakerTest do
  use ExUnit.Case, async: false

  alias Supavisor.CircuitBreaker

  setup do
    :ets.delete_all_objects(Supavisor.CircuitBreaker)
    :ok
  end

  describe "check/2" do
    test "returns :ok when no failures recorded" do
      assert :ok = CircuitBreaker.check("tenant1", :get_secrets)
    end

    test "returns :ok when circuit is closed" do
      CircuitBreaker.record_failure("tenant1", :get_secrets)
      assert :ok = CircuitBreaker.check("tenant1", :get_secrets)
    end

    test "returns error when circuit is open" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("tenant1", :get_secrets)
      end

      assert {:error, :circuit_open, blocked_until} =
               CircuitBreaker.check("tenant1", :get_secrets)

      assert is_integer(blocked_until)
      assert blocked_until > System.system_time(:second)
    end

    test "returns :ok after block period expires" do
      now = System.system_time(:second)

      key = {"tenant1", :get_secrets}
      state = %{failures: [now], blocked_until: now - 1}
      :ets.insert(CircuitBreaker, {key, state})

      assert :ok = CircuitBreaker.check("tenant1", :get_secrets)
    end
  end

  describe "record_failure/2" do
    test "records first failure" do
      CircuitBreaker.record_failure("tenant1", :get_secrets)

      assert [{_, %{failures: failures}}] = :ets.lookup(CircuitBreaker, {"tenant1", :get_secrets})
      assert length(failures) == 1
    end

    test "opens circuit when threshold exceeded" do
      for _ <- 1..4 do
        CircuitBreaker.record_failure("tenant1", :get_secrets)
      end

      assert :ok = CircuitBreaker.check("tenant1", :get_secrets)

      CircuitBreaker.record_failure("tenant1", :get_secrets)

      assert {:error, :circuit_open, _} = CircuitBreaker.check("tenant1", :get_secrets)
    end

    test "filters old failures outside window" do
      now = System.system_time(:second)
      old_time = now - 700

      key = {"tenant1", :get_secrets}
      state = %{failures: [old_time, old_time, old_time], blocked_until: nil}
      :ets.insert(CircuitBreaker, {key, state})

      CircuitBreaker.record_failure("tenant1", :get_secrets)

      assert [{_, %{failures: failures}}] = :ets.lookup(CircuitBreaker, key)
      assert length(failures) == 1
    end

    test "maintains separate state per tenant" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("tenant1", :get_secrets)
      end

      CircuitBreaker.record_failure("tenant2", :get_secrets)

      assert {:error, :circuit_open, _} = CircuitBreaker.check("tenant1", :get_secrets)
      assert :ok = CircuitBreaker.check("tenant2", :get_secrets)
    end

    test "maintains separate state per operation" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("tenant1", :get_secrets)
      end

      CircuitBreaker.record_failure("tenant1", :db_connection)

      assert {:error, :circuit_open, _} = CircuitBreaker.check("tenant1", :get_secrets)
      assert :ok = CircuitBreaker.check("tenant1", :db_connection)
    end

    test "db_connection requires 100 failures" do
      for _ <- 1..99 do
        CircuitBreaker.record_failure("tenant1", :db_connection)
      end

      assert :ok = CircuitBreaker.check("tenant1", :db_connection)

      CircuitBreaker.record_failure("tenant1", :db_connection)

      assert {:error, :circuit_open, _} = CircuitBreaker.check("tenant1", :db_connection)
    end
  end

  describe "clear/2" do
    test "removes circuit breaker state" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("tenant1", :get_secrets)
      end

      CircuitBreaker.clear("tenant1", :get_secrets)

      assert :ok = CircuitBreaker.check("tenant1", :get_secrets)
      assert [] = :ets.lookup(CircuitBreaker, {"tenant1", :get_secrets})
    end
  end

  describe "cleanup_stale_entries/0" do
    test "removes old entries" do
      now = System.system_time(:second)
      old_time = now - 2000

      key = {"tenant1", :get_secrets}
      state = %{failures: [old_time], blocked_until: nil}
      :ets.insert(CircuitBreaker, {key, state})

      deleted = CircuitBreaker.cleanup_stale_entries()

      assert deleted == 1
      assert [] = :ets.lookup(CircuitBreaker, key)
    end

    test "keeps recent entries" do
      CircuitBreaker.record_failure("tenant1", :get_secrets)

      deleted = CircuitBreaker.cleanup_stale_entries()

      assert deleted == 0
      assert [{_, _}] = :ets.lookup(CircuitBreaker, {"tenant1", :get_secrets})
    end

    test "removes expired blocks" do
      now = System.system_time(:second)
      old_time = now - 2000

      key = {"tenant1", :get_secrets}
      state = %{failures: [old_time], blocked_until: now - 100}
      :ets.insert(CircuitBreaker, {key, state})

      deleted = CircuitBreaker.cleanup_stale_entries()

      assert deleted == 1
    end

    test "keeps active blocks" do
      now = System.system_time(:second)

      key = {"tenant1", :get_secrets}
      state = %{failures: [now], blocked_until: now + 100}
      :ets.insert(CircuitBreaker, {key, state})

      deleted = CircuitBreaker.cleanup_stale_entries()

      assert deleted == 0
    end
  end

  describe "list_all_failures/1" do
    test "returns all failures for a given key" do
      CircuitBreaker.record_failure("tenant1", :get_secrets)
      CircuitBreaker.record_failure("tenant1", :db_connection)
      CircuitBreaker.record_failure("tenant2", :get_secrets)

      results = CircuitBreaker.list_all_failures("tenant1")

      assert length(results) == 2

      assert Enum.any?(results, fn
               {:get_secrets, %{failures: [_], blocked_until: nil}} -> true
               _ -> false
             end)

      assert Enum.any?(results, fn
               {:db_connection, %{failures: [_], blocked_until: nil}} -> true
               _ -> false
             end)
    end

    test "returns all blocked operations along with the timestamp" do
      CircuitBreaker.record_failure("tenant1", :get_secrets)
      CircuitBreaker.record_failure("tenant1", :db_connection)

      for _ <- 1..10 do
        CircuitBreaker.record_failure("tenant1", :auth_error)
      end

      CircuitBreaker.record_failure("tenant2", :get_secrets)

      assert {:error, :circuit_open, _} = CircuitBreaker.check("tenant1", :auth_error)

      assert [{:auth_error, %{blocked_until: blocked_until}}] = CircuitBreaker.blocked("tenant1")
      assert is_integer(blocked_until)
      assert blocked_until > System.system_time(:second)
    end
  end
end
