defmodule Supavisor.Support.Polling do
  @moduledoc """
  Polling utilities for tests.
  """

  @doc """
  Polls `fun` until it returns a truthy value or the timeout (in ms) is exceeded.

  Returns `:ok` on success, `:timeout` if the deadline is reached.
  Checks every 50 ms.
  """
  def wait_until(fun, remaining \\ 1000)
  def wait_until(_fun, remaining) when remaining <= 0, do: :timeout

  def wait_until(fun, remaining) do
    if fun.() do
      :ok
    else
      Process.sleep(50)
      wait_until(fun, remaining - 50)
    end
  end
end
