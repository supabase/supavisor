defmodule Supavisor.Support.Cluster do
  def apply_config(node) do
    for {app_name, _, _} <- Application.loaded_applications() do
      for {key, val} <- Application.get_all_env(app_name) do
        val =
          case {app_name, key} do
            {:supavisor, :proxy_port} ->
              Application.get_env(:supavisor, :secondary_proxy_port)

            {:supavisor, SupavisorWeb.Endpoint} ->
              put_in(val[:http],
                ip: {127, 0, 0, 1},
                port: Application.get_env(:supavisor, :secondary_http)
              )

            _ ->
              val
          end

        :rpc.call(node, Application, :put_env, [app_name, key, val, [persistent: true]])
      end
    end
  end
end
