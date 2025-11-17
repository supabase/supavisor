defmodule Supavisor.TenantCache do
  @moduledoc """
  Caches tenant-specific data that needs to survive child process restarts.
  """

  use GenServer

  def start_link(args) do
    GenServer.start_link(__MODULE__, args)
  end

  def init(%{id: id}) do
    table = :ets.new(:tenant_cache, [:set, :public])
    Registry.register(Supavisor.Registry.Tenants, {:cache, id}, table)
    {:ok, %{table: table, id: id}}
  end

  @spec get_parameter_status(Supavisor.id()) :: iodata() | []
  def get_parameter_status(id) do
    case Registry.lookup(Supavisor.Registry.Tenants, {:cache, id}) do
      [{_pid, table}] ->
        case :ets.lookup(table, :parameter_status) do
          [{:parameter_status, ps}] -> ps
          _ -> []
        end

      _ ->
        []
    end
  end

  @spec put_parameter_status(Supavisor.id(), iodata()) :: true
  def put_parameter_status(id, encoded_ps) do
    case Registry.lookup(Supavisor.Registry.Tenants, {:cache, id}) do
      [{_pid, table}] ->
        :ets.insert(table, {:parameter_status, encoded_ps})

      _ ->
        true
    end
  end
end
