defmodule Cluster.Strategy.Postgres do
  @moduledoc false

  use GenServer

  alias Cluster.Strategy
  alias Cluster.Strategy.State
  alias Cluster.Logger
  alias Postgrex, as: P

  @channel "cluster"
  def start_link(args), do: GenServer.start_link(__MODULE__, args)

  def init([state]) do
    new_config =
      state.config
      |> Keyword.put_new(:heartbeat_interval, 5_000)

    opts =
      Ecto.Repo.Supervisor.parse_url(state.config[:url])
      |> Keyword.put_new(:parameters, application_name: "cluster_node_#{node()}")
      |> Keyword.put_new(:auto_reconnect, true)

    meta = %{
      opts: opts,
      conn: nil,
      conn_notif: nil,
      heartbeat_ref: make_ref()
    }

    {:ok, %{state | config: new_config, meta: meta}, {:continue, :connect}}
  end

  def handle_continue(:connect, state) do
    with {:ok, conn} <- P.start_link(state.meta.opts),
         {:ok, conn_notif} <- P.Notifications.start_link(state.meta.opts),
         {_, _} <- P.Notifications.listen(conn_notif, @channel) do
      Logger.info(state.topology, "Connected to Postgres database")

      meta = %{
        state.meta
        | conn: conn,
          conn_notif: conn_notif,
          heartbeat_ref: heartbeat(0)
      }

      {:noreply, put_in(state.meta, meta)}
    else
      reason ->
        Logger.error(state.topology, "Failed to connect to Postgres: #{inspect(reason)}")

        {:stop, reason, state}
        {:noreply, state}
    end
  end

  def handle_info(:heartbeat, state) do
    Process.cancel_timer(state.meta.heartbeat_ref)
    P.query(state.meta.conn, "NOTIFY #{@channel}, '#{node()}'", [])
    ref = heartbeat(state.config[:heartbeat_interval])
    {:noreply, put_in(state.meta.heartbeat_ref, ref)}
  end

  def handle_info({:notification, _, _, _, node}, state) do
    node = String.to_atom(node)

    if node != node() do
      topology = state.topology
      Logger.debug(topology, "Trying to connect to node: #{node}")

      case Strategy.connect_nodes(topology, state.connect, state.list_nodes, [node]) do
        :ok ->
          Logger.debug(topology, "Connected to node: #{node}")

        {:error, _} ->
          Logger.error(topology, "Failed to connect to node: #{node}")
      end
    end

    {:noreply, state}
  end

  def handle_info(msg, state) do
    Logger.error(state.topology, "Undefined message #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  ### Internal functions
  @spec heartbeat(non_neg_integer()) :: reference()
  defp heartbeat(interval) do
    Process.send_after(self(), :heartbeat, interval)
  end
end
