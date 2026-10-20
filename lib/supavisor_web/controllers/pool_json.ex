defmodule SupavisorWeb.PoolJSON do
  require Supavisor

  alias SupavisorWeb.PoolId

  @doc """
  Renders a tenant's pools. Node errors are reported as `"unreachable"`; the actual
  reason is only logged.
  """
  def index(%{result: %{pools: pools, errors: errors}}) do
    %{
      pools: Enum.map(pools, &pool/1),
      errors: Map.new(errors, fn {node, _reason} -> {to_string(node), "unreachable"} end)
    }
  end

  defp pool(pool) do
    %{
      id: PoolId.id_to_map(pool.id),
      token: PoolId.encode_token(pool.id),
      node: to_string(pool.node),
      host: pool.host,
      port: pool.port,
      clients: pool.clients,
      connections: pool.connections
    }
  end

  @doc """
  Renders the pools being moved by `Supavisor.rebalance/1`.
  """
  def rebalance(%{result: result}) do
    moves =
      for {node, {:ok, moves}} <- result, {id, target} <- moves do
        Supavisor.id(tenant: tenant, user: user, mode: mode, db: db) = id

        %{
          tenant: tenant,
          user: user,
          mode: mode,
          database: db,
          from_node: node,
          to_node: target
        }
      end

    errors = for {node, {:error, reason}} <- result, into: %{}, do: {node, inspect(reason)}

    %{moves: moves, errors: errors}
  end
end
