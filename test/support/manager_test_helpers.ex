defmodule Supavisor.Support.ManagerTestHelpers do
  @moduledoc """
  Helpers for simulating a sibling `Supavisor.Manager` registration in tests,
  without booting a real `Manager` (which needs real tenant/DB config to `init/1`).

  Lives under `test/support` (rather than inline in a `*_test.exs` file) so the compiled
  module is present on a peer test node's code path — `*_test.exs` files are compiled
  in-memory only and aren't visible to a separate BEAM node started via `Node.spawn/4`.
  """

  @doc """
  Registers `sibling_id` under `{:manager, sibling_id}` in `Supavisor.Registry.Tenants` on
  whichever node this runs on, then blocks (holding the registration) until told to `:stop`.

  Sends `:registered` back to `test_pid` once registration completes, so the caller can
  synchronize instead of racing a freshly spawned process.
  """
  @spec sibling_loop(Supavisor.id(), pid()) :: :ok
  def sibling_loop(sibling_id, test_pid) do
    Registry.register(Supavisor.Registry.Tenants, {:manager, sibling_id}, nil)
    send(test_pid, :registered)

    receive do
      :stop -> :ok
    end
  end
end
