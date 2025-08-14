defmodule Supavisor.Support.Cluster do
  @moduledoc """
  This module provides functionality to help handle distributive mode for testing.
  """

  def start_node(name \\ :peer.random_name()) do
    start_peer_node(name, clustered: true)
  end

  def start_node_unclustered(name \\ :peer.random_name(), port_offset \\ 0) do
    start_peer_node(name, clustered: false, port_offset: port_offset)
  end

  defp start_peer_node(name, opts) do
    clustered = Keyword.get(opts, :clustered, true)
    port_offset = Keyword.get(opts, :port_offset, 0)

    {:ok, pid, node} = create_peer(name)
    setup_peer_logging(pid)
    apply_peer_config(pid, clustered, port_offset)
    :peer.call(pid, Application, :ensure_all_started, [:supavisor])

    {:ok, pid, node}
  end

  defp create_peer(name) do
    ExUnit.Callbacks.start_supervised(%{
      id: {:peer, name},
      start:
        {:peer, :start_link,
         [
           %{
             name: name,
             host: ~c"127.0.0.1",
             longnames: true,
             connection: :standard_io
           }
         ]}
    })
  end

  defp setup_peer_logging(pid) do
    :peer.call(pid, :logger, :add_primary_filter, [
      :sasl_filter,
      {&:logger_filters.domain/2, {:stop, :sub, [:otp, :sasl]}}
    ])

    :peer.call(pid, :logger, :set_primary_config, [:level, :all])
    true = :peer.call(pid, :code, :set_path, [:code.get_path()])
  end

  defp apply_peer_config(pid, clustered, port_offset) do
    for {app_name, _, _} <- Application.loaded_applications() do
      for {key, val} <- Application.get_all_env(app_name) do
        new_val = transform_config_value({app_name, key}, val, clustered, port_offset)
        :peer.call(pid, Application, :put_env, [app_name, key, new_val])
      end
    end
  end

  defp transform_config_value(
         {:supavisor, :proxy_port_transaction},
         _val,
         _clustered,
         port_offset
       ) do
    Application.get_env(:supavisor, :secondary_proxy_port) + port_offset
  end

  defp transform_config_value(
         {:supavisor, SupavisorWeb.Endpoint},
         val,
         _clustered,
         _port_offset
       ) do
    put_in(val[:http], ip: {127, 0, 0, 1}, port: 0)
  end

  defp transform_config_value({:supavisor, :region}, _val, _clustered, _port_offset) do
    "usa"
  end

  defp transform_config_value(
         {:supavisor, :availability_zone},
         _val,
         _clustered,
         _port_offset
       ) do
    "ap-southeast-1c"
  end

  defp transform_config_value(
         {:supavisor, :session_proxy_ports},
         _val,
         _clustered,
         port_offset
       ) do
    apply_port_offset(:session_proxy_ports, port_offset)
  end

  defp transform_config_value(
         {:supavisor, :transaction_proxy_ports},
         _val,
         _clustered,
         port_offset
       ) do
    apply_port_offset(:transaction_proxy_ports, port_offset)
  end

  defp transform_config_value(
         {:libcluster, :topologies},
         _val,
         clustered,
         _port_offset
       )
       when not clustered do
    []
  end

  defp transform_config_value(_key, val, _clustered, _port_offset) do
    val
  end

  defp apply_port_offset(port_config_key, port_offset) do
    Application.get_env(:supavisor, port_config_key)
    |> Enum.map(&(&1 + port_offset * 200))
  end
end
