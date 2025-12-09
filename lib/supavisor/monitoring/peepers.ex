defmodule Supavisor.Monitoring.Peepers do
  @moduledoc """
  Native Prometheus exporter for Peep metrics.

  Provides high-performance Prometheus text format generation using Rust NIFs.
  This is significantly faster and uses less memory than the pure Elixir implementation.
  """

  use Rustler, otp_app: :supavisor, crate: "peepers"

  @doc """
  Exports metrics in Prometheus text format.
  Takes a map of metrics from Peep.get_all_metrics/1 and returns a binary string.

  ## Example

      iex> Peep.get_all_metrics(:my_metrics)
      ...> |> Supavisor.Monitoring.Peepers.prometheus_export()
      "# HELP http_requests_total Total HTTP requests\\n# TYPE http_requests_total counter\\n..."
  """
  def prometheus_export(_metrics_map), do: :erlang.nif_error(:nif_not_loaded)
end
