defmodule Supavisor.Asserts do
  @doc """
  Asserts that `function` will eventually success. Fails otherwise.

  It performs `repeats` checks with `delay` milliseconds between each check.
  """
  def assert_eventually(repeats \\ 5, delay \\ 1000, function)

  def assert_eventually(0, _, _) do
    raise ExUnit.AssertionError, message: "Expected function to return truthy value"
  end

  def assert_eventually(n, delay, func) do
    if func.() do
      :ok
    else
      Process.sleep(delay)
      assert_eventually(n - 1, delay, func)
    end
  end

  @doc """
  Asserts that `function` will eventually fail. Fails otherwise.

  It performs `repeats` checks with `delay` milliseconds between each check.
  """
  def refute_eventually(repeats \\ 5, delay \\ 1000, function)

  def refute_eventually(0, _, _) do
    raise ExUnit.AssertionError, message: "Expected function to return falsey value"
  end

  def refute_eventually(n, delay, func) do
    if func.() do
      Process.sleep(delay)
      refute_eventually(n - 1, delay, func)
    else
      :ok
    end
  end
end
