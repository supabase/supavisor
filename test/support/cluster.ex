defmodule Supavisor.Support.Cluster do
  @moduledoc """
  This module provides functionality to help handle distributive mode for testing.
  """

  def apply_config(node) do
    for {app_name, _, _} <- Application.loaded_applications() do
      for {key, val} <- Application.get_all_env(app_name) do
        val =
          case {app_name, key} do
            {:supavisor, :proxy_port_transaction} ->
              Application.get_env(:supavisor, :secondary_proxy_port)

            {:supavisor, SupavisorWeb.Endpoint} ->
              put_in(val[:http],
                ip: {127, 0, 0, 1},
                port: Application.get_env(:supavisor, :secondary_http)
              )

            {:supavisor, :region} ->
              "usa"

            _ ->
              val
          end

        :rpc.call(node, Application, :put_env, [app_name, key, val, [persistent: true]])
        :rpc.call(node, Supavisor.Monitoring.PromEx, :set_metrics_tags, [])
      end
    end
  end
end
