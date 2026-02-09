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
    test "clears circuit breaker state" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("tenant1", :get_secrets)
      end

      CircuitBreaker.clear("tenant1", :get_secrets)

      assert :ok = CircuitBreaker.check("tenant1", :get_secrets)
      assert [] = :ets.lookup(CircuitBreaker, {"tenant1", :get_secrets})
    end
  end

  describe "clear_local/2" do
    test "clears circuit breaker state on current node" do
      key = "tenant1"

      for _ <- 1..10 do
        CircuitBreaker.record_failure(key, :auth_error)
      end

      assert {:error, :circuit_open, _} = CircuitBreaker.check(key, :auth_error)

      CircuitBreaker.clear_local(key, :auth_error)

      assert :ok = CircuitBreaker.check(key, :auth_error)
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

  describe "opened/2" do
    test "returns blocked operations with key and blocked_until timestamp" do
      for _ <- 1..10 do
        CircuitBreaker.record_failure("tenant1", :auth_error)
      end

      assert {:error, :circuit_open, _} = CircuitBreaker.check("tenant1", :auth_error)

      assert [{"tenant1", blocked_until}] = CircuitBreaker.opened("tenant1", :auth_error)
      assert is_integer(blocked_until)
      assert blocked_until > System.system_time(:second)
    end

    test "returns empty list when operation is not blocked" do
      CircuitBreaker.record_failure("tenant1", :get_secrets)
      assert [] = CircuitBreaker.opened("tenant1", :get_secrets)
    end

    test "returns empty list for unknown key" do
      assert [] = CircuitBreaker.opened("unknown_tenant", :auth_error)
    end

    test "supports pattern matching with {tenant, :_} to find all IPs" do
      ip1 = "10.0.0.1"
      ip2 = "10.0.0.2"

      for _ <- 1..10 do
        CircuitBreaker.record_failure({"tenant1", ip1}, :auth_error)
        CircuitBreaker.record_failure({"tenant1", ip2}, :auth_error)
      end

      assert {:error, :circuit_open, _} = CircuitBreaker.check({"tenant1", ip1}, :auth_error)
      assert {:error, :circuit_open, _} = CircuitBreaker.check({"tenant1", ip2}, :auth_error)

      bans = CircuitBreaker.opened({"tenant1", :_}, :auth_error)
      assert length(bans) == 2

      assert Enum.all?(bans, fn {{tenant, ip}, blocked_until} ->
               tenant == "tenant1" and ip in [ip1, ip2] and is_integer(blocked_until) and
                 blocked_until > System.system_time(:second)
             end)
    end

    test "returns empty list when no keys match pattern" do
      assert [] = CircuitBreaker.opened({"unknown_tenant", :_}, :auth_error)
    end

    test "only returns keys matching the exact prefix in pattern and the operation" do
      ip1 = "10.0.0.1"
      ip2 = "10.0.0.2"

      for _ <- 1..10 do
        CircuitBreaker.record_failure({"tenant1", ip1}, :auth_error)
        CircuitBreaker.record_failure({"tenant1", ip1}, :get_secrets)
        CircuitBreaker.record_failure({"tenant2", ip2}, :auth_error)
      end

      assert {:error, :circuit_open, _} = CircuitBreaker.check({"tenant1", ip1}, :auth_error)
      assert {:error, :circuit_open, _} = CircuitBreaker.check({"tenant1", ip1}, :get_secrets)

      assert {:error, :circuit_open, _} = CircuitBreaker.check({"tenant2", ip2}, :auth_error)

      assert [{{"tenant1", ^ip1}, blocked_until}] =
               CircuitBreaker.opened({"tenant1", :_}, :auth_error)

      assert is_integer(blocked_until)
      assert blocked_until > System.system_time(:second)
    end
  end

  describe "open_local/3" do
    test "sets circuit breaker to open without previous failures" do
      key = "tenant1"
      blocked_until = System.system_time(:second) + 300

      CircuitBreaker.open_local(key, :auth_error, blocked_until)

      assert {:error, :circuit_open, ^blocked_until} =
               CircuitBreaker.check(key, :auth_error)
    end

    test "sets circuit breaker to open with previous failures" do
      key = "tenant1"
      CircuitBreaker.record_failure(key, :auth_error)

      blocked_until = System.system_time(:second) + 300
      CircuitBreaker.open_local(key, :auth_error, blocked_until)

      assert {:error, :circuit_open, ^blocked_until} =
               CircuitBreaker.check(key, :auth_error)
    end
  end
end
