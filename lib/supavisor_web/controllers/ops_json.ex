defmodule SupavisorWeb.OpsJSON do
  def error(%{error: error}), do: %{error: error}
end
