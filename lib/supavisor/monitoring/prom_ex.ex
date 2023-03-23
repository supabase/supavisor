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
    |> :ets.select_delete([{{{:_, %{tenant: tenant}}, :_}, [], [nil]}])
  end
end
