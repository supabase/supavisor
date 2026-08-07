defmodule Supavisor.MetricsPusher do
  @moduledoc """
  GenServer that periodically pushes Prometheus metrics to an endpoint.

  Only starts if `url` is configured.
  Pushes metrics every 30 seconds (configurable) to the configured URL endpoint.
  """

  use GenServer

  require Logger

  alias Supavisor.Monitoring.PromEx

  @type t :: %__MODULE__{
          push_ref: reference() | nil,
          interval: pos_integer() | nil,
          req_options: keyword() | nil
        }

  defstruct [:push_ref, :interval, :req_options]

  @spec start_link(keyword()) :: {:ok, pid()} | :ignore
  def start_link(opts) do
    url = Keyword.get(opts, :url, Application.get_env(:supavisor, :metrics_pusher_url))

    if is_binary(url) do
      GenServer.start_link(__MODULE__, opts, name: __MODULE__)
    else
      Logger.warning("MetricsPusher not started: url must be configured")

      :ignore
    end
  end

  @impl true
  def init(opts) do
    url = Keyword.get(opts, :url, Application.get_env(:supavisor, :metrics_pusher_url))

    user =
      Keyword.get(opts, :user, Application.get_env(:supavisor, :metrics_pusher_user, "supavisor"))

    auth = Keyword.get(opts, :auth, Application.get_env(:supavisor, :metrics_pusher_auth))

    interval =
      Keyword.get(
        opts,
        :interval,
        Application.get_env(:supavisor, :metrics_pusher_interval_ms, :timer.seconds(30))
      )

    timeout =
      Keyword.get(
        opts,
        :timeout,
        Application.get_env(:supavisor, :metrics_pusher_timeout_ms, :timer.seconds(15))
      )

    compress =
      Keyword.get(
        opts,
        :compress,
        Application.get_env(:supavisor, :metrics_pusher_compress, true)
      )

    extra_labels =
      Keyword.get(
        opts,
        :extra_labels,
        Application.get_env(:supavisor, :metrics_pusher_extra_labels, [])
      )

    params = Enum.map(extra_labels, fn {k, v} -> {:extra_label, "#{k}=#{v}"} end)

    Logger.info(
      "Starting MetricsPusher (url: #{url}, interval: #{interval}ms, compress: #{compress})"
    )

    headers = [{"content-type", "text/plain"}]

    basic_auth = if auth, do: [auth: {:basic, "#{user}:#{auth}"}], else: []

    req_options =
      [
        method: :post,
        url: url,
        headers: headers,
        compress_body: compress,
        receive_timeout: timeout,
        params: params
      ]
      |> Keyword.merge(basic_auth)
      |> Keyword.merge(Application.get_env(:supavisor, :metrics_pusher_req_options, []))

    state = %__MODULE__{
      push_ref: schedule_push(interval),
      interval: interval,
      req_options: req_options
    }

    {:ok, state}
  end

  @impl true
  def handle_info(:push, state) do
    {exec_time, _} = :timer.tc(fn -> push(state.req_options) end, :millisecond)

    if exec_time > :timer.seconds(5) do
      Logger.warning("Metrics push took: #{exec_time} ms")
    end

    {:noreply, %{state | push_ref: schedule_push(state.interval)}}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.error("MetricsPusher received unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  defp schedule_push(delay), do: Process.send_after(self(), :push, delay)

  # Unlike realtime, which keeps separate global and per-tenant PromEx trees,
  # supavisor keeps every plugin (Application, Beam, Ecto, OsMon, NetStat,
  # Tenant, Cluster) in a single collector. PromEx.get_metrics/0 is this node's
  # own local export (no cross-node RPC fan-out) and already includes any
  # tenant-tagged series for tenants attached to this node, so one push per
  # tick is enough. Each node pushing only its own metrics (tagged with its
  # node identity via global_tags) avoids the O(n^2) RPC fan-out that
  # PromEx.get_cluster_metrics/0 would cause if every node in the cluster
  # pushed on its own interval.
  defp push(req_options) do
    task =
      Task.Supervisor.async_nolink(Supavisor.TaskSupervisor, fn -> push_metrics(req_options) end)

    case Task.yield(task, :timer.minutes(1)) do
      nil ->
        Task.shutdown(task, :brutal_kill)
        Logger.error("MetricsPusher: Task timed out: #{inspect(task)}")

      {:exit, reason} ->
        Logger.error("MetricsPusher: Task exited with reason: #{inspect(reason)}")

      {:ok, _} ->
        :ok
    end
  end

  defp push_metrics(req_options) do
    case send_metrics(req_options, PromEx.get_metrics()) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error(
          "MetricsPusher: Failed to push metrics to #{req_options[:url]}: #{inspect(reason)}"
        )

        :ok
    end
  rescue
    error ->
      Logger.error("MetricsPusher: Exception during push: #{inspect(error)}")
      :ok
  end

  defp send_metrics(req_options, metrics) do
    [{:body, metrics} | req_options] |> Req.request() |> handle_response()
  end

  defp handle_response({:ok, %{status: status}}) when status in 200..299, do: :ok

  defp handle_response({:ok, %{status: status} = response}),
    do: {:error, {:http_error, status, response.body}}

  defp handle_response({:error, reason}), do: {:error, reason}
end
