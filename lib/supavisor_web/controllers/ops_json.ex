defmodule SupavisorWeb.OpsJSON do
  @doc """
  Renders the cluster's nodes. Node errors are reported as `"unreachable"`.
  """
  def index(%{result: %{nodes: nodes, errors: errors}}) do
    %{
      nodes: Enum.map(nodes, &node_info/1),
      errors: Map.new(errors, fn {node, _reason} -> {to_string(node), "unreachable"} end)
    }
  end

  def error(%{error: error}), do: %{error: error}

  defp node_info(info) do
    %{
      node: to_string(info.node),
      host: info.host,
      uptime_ms: info.uptime_ms,
      version: info.version,
      health: health(info.health)
    }
  end

  defp health(:ok), do: %{status: "healthy", failed_checks: []}

  defp health({:error, :failed_checks, checks}),
    do: %{status: "unhealthy", failed_checks: Enum.map(checks, &to_string/1)}
end
