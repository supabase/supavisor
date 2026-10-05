defmodule Supavisor.PromEx.Plugins.CGroup do
  @moduledoc """
  Polls cgroup v2 memory.
  """

  use PromEx.Plugin

  @event_memory [:supavisor, :prom_ex, :osmon, :cgroup_memory]
  @prefix [:supavisor, :prom_ex]
  @proc_self_cgroup "/proc/self/cgroup"
  @cgroup_root "/sys/fs/cgroup"
  @unlimited_memory 9_223_372_036_854_775_807

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      memory_metrics(poll_rate)
    ]
  end

  defp memory_metrics(poll_rate) do
    Polling.build(
      :supavisor_osmon_cgroup_memory_events,
      poll_rate,
      {__MODULE__, :execute_memory_metrics, []},
      [
        last_value(
          @prefix ++ [:osmon, :cgroup, :memory_current],
          event_name: @event_memory,
          description: "Current memory usage of the cgroup, in bytes.",
          unit: :bytes,
          measurement: :memory_current
        ),
        last_value(
          @prefix ++ [:osmon, :cgroup, :memory_max],
          event_name: @event_memory,
          description:
            "Memory usage limit of the cgroup, in bytes. #{@unlimited_memory} means unlimited (or undetermined).",
          unit: :bytes,
          measurement: :memory_max
        )
      ]
    )
  end

  @spec execute_memory_metrics() :: :ok
  def execute_memory_metrics do
    case memory() do
      {:ok, stats} -> emit(stats)
      :error -> :ok
    end
  end

  @spec execute_memory_metrics(Path.t(), Path.t()) :: :ok
  def execute_memory_metrics(current_path, max_path) do
    case memory(current_path, max_path) do
      {:ok, stats} -> emit(stats)
      :error -> :ok
    end
  end

  defp emit(stats), do: :telemetry.execute(@event_memory, stats, %{})

  @doc "Sentinel reported as memory_max when the cgroup has no limit, or none could be determined."
  @spec unlimited_memory() :: pos_integer()
  def unlimited_memory, do: @unlimited_memory

  @type memory_stats :: %{memory_current: non_neg_integer(), memory_max: pos_integer()}

  @doc """
  Reads memory.current/memory.max from the caller's own cgroup, resolved via
  /proc/self/cgroup.
  """
  @spec memory() :: {:ok, memory_stats()} | :error
  def memory do
    with {:ok, dir} <- cached_cgroup_dir() do
      memory(Path.join(dir, "memory.current"), Path.join(dir, "memory.max"))
    end
  end

  # sobelow_skip ["Traversal.FileModule"]
  @spec memory(Path.t(), Path.t()) :: {:ok, memory_stats()} | :error
  def memory(current_path, max_path) do
    with {:ok, current_content} <- File.read(current_path),
         {:ok, current} <- parse_int(current_content) do
      {:ok, %{memory_current: current, memory_max: read_max(max_path)}}
    else
      _ -> :error
    end
  end

  @doc """
  Resolves the absolute cgroup v2 directory this process belongs to, e.g.
  "/sys/fs/cgroup/system.slice/supavisor.service".
  """
  # sobelow_skip ["Traversal.FileModule"]
  @spec cgroup_dir(Path.t(), Path.t()) :: {:ok, Path.t()} | :error
  def cgroup_dir(proc_cgroup_path \\ @proc_self_cgroup, root \\ @cgroup_root) do
    with {:ok, content} <- File.read(proc_cgroup_path),
         {:ok, relative_path} <- parse_cgroup_path(content) do
      {:ok, Path.join(root, relative_path)}
    else
      _ -> :error
    end
  end

  @persistent_term_key {__MODULE__, :cgroup_dir}

  # The process's own cgroup can't change for its lifetime, so cache it
  # instead of re-reading /proc/self/cgroup on every poll tick.
  defp cached_cgroup_dir do
    case :persistent_term.get(@persistent_term_key, :unset) do
      :unset ->
        with {:ok, _dir} = result <- cgroup_dir() do
          :persistent_term.put(@persistent_term_key, result)
          result
        end

      cached ->
        cached
    end
  end

  @spec parse_cgroup_path(String.t()) :: {:ok, String.t()} | :error
  def parse_cgroup_path(content) do
    content
    |> String.split("\n", trim: true)
    |> Enum.find_value(fn
      "0::" <> path -> {:ok, String.trim_leading(path, "/")}
      _ -> nil
    end) || :error
  end

  defp read_max(max_path) do
    with {:ok, max_content} <- File.read(max_path),
         {:ok, max} <- parse_int(max_content) do
      max
    else
      _ -> @unlimited_memory
    end
  end

  defp parse_int(content) do
    case content |> String.trim() |> Integer.parse() do
      {int, ""} -> {:ok, int}
      _ -> :error
    end
  end
end
