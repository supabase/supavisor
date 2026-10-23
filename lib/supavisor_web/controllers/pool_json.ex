defmodule SupavisorWeb.PoolJSON do
  require Supavisor

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

  def error(%{error: error}), do: %{error: error}

  defp pool(pool) do
    %{
      id: id(pool.id),
      pid: encode_pid(pool.pid),
      pid_label: pool.pid_label,
      status: pool.status,
      node: to_string(pool.node),
      db_host: pool.db_host,
      db_port: pool.db_port,
      clients: pool.clients,
      db_connections: pool.db_connections
    }
  end

  defp id(
         Supavisor.id(
           type: type,
           tenant: tenant,
           user: user,
           mode: mode,
           db: db,
           search_path: search_path,
           upstream_tls: upstream_tls
         )
       ) do
    %{
      type: type,
      tenant: tenant,
      user: user,
      mode: mode,
      db: db,
      search_path: search_path,
      upstream_tls: upstream_tls
    }
  end

  # The encoding carries the pid's node and the node's incarnation, so it identifies
  # this exact pool supervisor anywhere in the cluster.
  defp encode_pid(pid), do: pid |> :erlang.term_to_binary() |> Base.url_encode64(padding: false)

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
