defmodule Supavisor.HealthTest do
  use ExUnit.Case, async: true

  alias Supavisor.Health

  describe "health_check/1" do
    test "returns :ok when all health checks pass" do
      assert :ok = Health.health_check()
    end

    test "returns failing checks" do
      assert {:error, :failed_checks, [:failing_check]} =
               Health.health_check(failing_check: {__MODULE__, :failing_check, []})
    end

    test "returns checks raising exceptions" do
      assert {:error, :failed_checks, [:exception_check]} =
               Health.health_check(exception_check: {__MODULE__, :exception_check, []})
    end

    test "returns checks exiting" do
      assert {:error, :failed_checks, [:exit_check]} =
               Health.health_check(exit_check: {__MODULE__, :exit_check, []})
    end

    test "kills and fails a check that does not finish in time" do
      checks = [
        passing_check: {__MODULE__, :passing_check, []},
        hanging_check: {__MODULE__, :hanging_check, [self()]}
      ]

      assert {:error, :failed_checks, [:hanging_check]} = Health.health_check(checks, 100)

      assert_receive {:hanging, pid}
      refute Process.alive?(pid)
    end

    test "returns checks with invalid responses" do
      assert {:error, :failed_checks, [:invalid_response_check]} =
               Health.health_check(
                 invalid_response_check: {__MODULE__, :invalid_response_check, []}
               )
    end
  end

  def failing_check(_args) do
    false
  end

  def exception_check(_args) do
    raise "exception"
  end

  def exit_check(_args) do
    exit(:whoops)
  end

  def passing_check, do: true

  def hanging_check(test_pid) do
    send(test_pid, {:hanging, self()})
    Process.sleep(:infinity)
  end

  def invalid_response_check(_args) do
    {:error, :invalid_response}
  end
end
