defmodule Supavisor.PromEx.Plugins.Ranch do
  @moduledoc """
  Polls ranch connection counters for all running ranch listeners.
  """

  use PromEx.Plugin

  @event [:supavisor, :prom_ex, :ranch]

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      Polling.build(
        :supavisor_ranch_events,
        poll_rate,
        {__MODULE__, :execute_ranch_metrics, []},
        [
          last_value(
            @event ++ [:connections, :accepted],
            event_name: @event,
            description: "Cumulative number of connections accepted by the listener.",
            measurement: :accepted,
            tags: [:listener],
            reporter_options: [prometheus_type: "counter"]
          ),
          last_value(
            @event ++ [:connections, :terminated],
            event_name: @event,
            description: "Cumulative number of connections terminated by the listener.",
            measurement: :terminated,
            tags: [:listener],
            reporter_options: [prometheus_type: "counter"]
          )
        ]
      )
    ]
  end

  @spec execute_ranch_metrics() :: :ok
  def execute_ranch_metrics do
    Enum.each(:ranch_server.get_listener_sups(), fn {ref, _pid} ->
      emit_listener_metrics(ref)
    end)
  end

  # ranch keeps one {accept, terminate} counter pair per conns_sup; it only
  # exposes them via ranch:info/1, which also makes a gen_server call into
  # every conns_sup, so read the counters directly instead
  defp emit_listener_metrics(ref) do
    counters = :ranch_server.get_stats_counters(ref)
    %{size: size} = :counters.info(counters)

    # ranch bumps accept before terminate for every connection, so reading each
    # sup's terminate counter before its accept counter keeps accepted >= terminated
    {accepted, terminated} =
      1..size//1
      |> Stream.chunk_every(2)
      |> Enum.reduce({0, 0}, fn [accept_idx, terminate_idx], {accepted, terminated} ->
        terminated = terminated + :counters.get(counters, terminate_idx)
        accepted = accepted + :counters.get(counters, accept_idx)
        {accepted, terminated}
      end)

    :telemetry.execute(
      @event,
      %{accepted: accepted, terminated: terminated},
      %{listener: format_ref(ref)}
    )
  rescue
    # listener stopped between enumeration and counter lookup
    ArgumentError -> :ok
  end

  @spec format_ref(:ranch.ref()) :: String.t()
  def format_ref({:pg_proxy_internal, mode, shard}), do: "pg_proxy_internal_#{mode}_#{shard}"
  def format_ref(ref) when is_atom(ref), do: Atom.to_string(ref)
  def format_ref(ref), do: inspect(ref)
end
