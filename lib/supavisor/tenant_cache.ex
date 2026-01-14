defmodule Supavisor.TenantCache do
  @moduledoc """
  Caches tenant-specific data that needs to survive child process restarts.

  We use this to store `upstream_cache_secrets` and `parameter_status`. This
  allows these values to be updated and retrieved anytime, and automatically
  cleans them up if the pool is restarted.
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

  @spec get_upstream_auth_secrets(Supavisor.id()) ::
          {:ok, {atom(), function()}} | {:error, :not_found}
  def get_upstream_auth_secrets(id) do
    case Registry.lookup(Supavisor.Registry.Tenants, {:cache, id}) do
      [{_pid, table}] ->
        case :ets.lookup(table, :upstream_auth_secrets) do
          [{:upstream_auth_secrets, secrets}] -> {:ok, secrets}
          _ -> {:error, :not_found}
        end

      _ ->
        {:error, :not_found}
    end
  end

  @spec put_upstream_auth_secrets(Supavisor.id(), {atom(), function()}) :: true
  def put_upstream_auth_secrets(id, secrets) do
    case Registry.lookup(Supavisor.Registry.Tenants, {:cache, id}) do
      [{_pid, table}] ->
        :ets.insert(table, {:upstream_auth_secrets, secrets})

      _ ->
        true
    end
  end
end
