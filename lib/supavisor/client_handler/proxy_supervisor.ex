defmodule Supavisor.ClientHandler.ProxySupervisor do
  @moduledoc """
  Wrapping supervisor for proxy connections of a single tenant.

  Children:
    1. A DynamicSupervisor (`:max_children` enforces the connection limit),
       registered in `Supavisor.Registry.Tenants` under `{:proxy_dyn_sup, id}`.
    2. A watchdog (significant child) that terminates when the DynamicSupervisor
       is empty, triggering `auto_shutdown: :any_significant` on this supervisor.
  """

  use Supervisor

  alias Supavisor.ClientHandler.ProxySupervisorWatchdog

  @registry Supavisor.Registry.Tenants

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts)
  end

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor,
      restart: :temporary
    }
  end

  @doc """
  Starts a child under the proxy DynamicSupervisor.

  Returns `{:ok, pid}` on success, `{:error, :max_children}` if the
  connection limit has been reached, or `{:error, term}` on other failures.
  """
  def start_connection(id, child_spec) do
    [{dyn_sup, _}] = Registry.lookup(@registry, {:proxy_dyn_sup, id})
    DynamicSupervisor.start_child(dyn_sup, child_spec)
  end

  @doc """
  Returns the watchdog pid for the given proxy supervisor.
  """
  def get_watchdog(proxy_sup) do
    {_, pid, _, _} =
      proxy_sup
      |> Supervisor.which_children()
      |> List.keyfind(:watchdog, 0)

    pid
  end

  @impl true
  def init(opts) do
    id = Keyword.fetch!(opts, :id)
    max_clients = Keyword.fetch!(opts, :max_clients)
    watchdog_opts = Keyword.get(opts, :watchdog_opts, [])

    children = [
      %{
        id: :connections,
        start:
          {DynamicSupervisor, :start_link,
           [
             [
               strategy: :one_for_one,
               max_children: max_clients,
               name: {:via, Registry, {@registry, {:proxy_dyn_sup, id}}}
             ]
           ]},
        type: :supervisor
      },
      %{
        id: :watchdog,
        start: {ProxySupervisorWatchdog, :start_link, [id, watchdog_opts]},
        significant: true,
        restart: :temporary
      }
    ]

    Supervisor.init(children, strategy: :one_for_one, auto_shutdown: :any_significant)
  end
end
