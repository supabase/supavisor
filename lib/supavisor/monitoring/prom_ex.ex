defmodule Supavisor.Monitoring.PromEx do
  @moduledoc """
  This module configures the PromEx application for Supavisor. It defines
  the plugins used for collecting metrics, including built-in plugins and custom ones,
  and provides a function to remove remote metrics associated with a specific tenant.
  """

  use PromEx, otp_app: :supavisor

  alias PromEx.Plugins
  alias Supavisor.PromEx.Plugins.{OsMon, Tenant}

  @impl true
  def plugins do
    poll_rate = Application.get_env(:supavisor, :prom_poll_rate)

    [
      # PromEx built in plugins
      Plugins.Application,
      Plugins.Beam,
      {Plugins.Phoenix, router: SupavisorWeb.Router, endpoint: SupavisorWeb.Endpoint},
      Plugins.Ecto,

      # Custom PromEx metrics plugins
      {OsMon, poll_rate: poll_rate},
      {Tenant, poll_rate: poll_rate}
    ]
  end

  @spec remove_metrics(String.t()) :: non_neg_integer()
  def remove_metrics(tenant) do
    Supavisor.Monitoring.PromEx.Metrics
    |> :ets.select_delete([{{{:_, %{tenant: tenant}}, :_}, [], [true]}])
  end

  @spec set_metrics_tags() :: :ok
  def set_metrics_tags() do
    [_, host] = node() |> Atom.to_string() |> String.split("@")

    metrics_tags = %{
      region: Application.get_env(:supavisor, :fly_region),
      node_host: host,
      short_alloc_id: short_node_id()
    }

    Application.put_env(:supavisor, :metrics_tags, metrics_tags)
  end

  @spec short_node_id() :: String.t()
  def short_node_id() do
    fly_alloc_id = Application.get_env(:supavisor, :fly_alloc_id)

    case String.split(fly_alloc_id, "-", parts: 2) do
      [short_alloc_id, _] -> short_alloc_id
      _ -> fly_alloc_id
    end
  end

  @spec get_metrics() :: String.t()
  def get_metrics() do
    %{
      region: region,
      node_host: host,
      short_alloc_id: short_alloc_id
    } = Application.get_env(:supavisor, :metrics_tags)

    def_tags = "host=\"#{host}\",region=\"#{region}\",id=\"#{short_alloc_id}\""

    metrics =
      PromEx.get_metrics(__MODULE__)
      |> String.split("\n")
      |> Enum.map(&parse_and_add_tags(&1, def_tags))
      |> Enum.join("\n")

    __MODULE__.__ets_cron_flusher_name__()
    |> PromEx.ETSCronFlusher.defer_ets_flush()

    metrics
  end

  @spec parse_and_add_tags(String.t(), String.t()) :: String.t()
  def parse_and_add_tags(line, def_tags) do
    case Regex.run(~r/(?!\#)^(\w+)(?:{(.*?)})?\s*(.+)$/, line) do
      nil ->
        line

      [_, key, tags, value] ->
        tags =
          if tags == "" do
            def_tags
          else
            "#{tags},#{def_tags}"
          end

        "#{key}{#{tags}} #{value}"
    end
  end
end
