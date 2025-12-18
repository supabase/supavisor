defmodule Supavisor.ErlSysMon do
  @moduledoc """
  Logs Erlang System Monitor events.
  """

  use GenServer

  alias Supavisor.Helpers

  require Logger

  @defaults [
    :busy_dist_port,
    :busy_port,
    {:long_gc, 500},
    {:long_schedule, 500},
    {:long_message_queue, {0, 1_000}},
    {:large_heap, Helpers.mb_to_words(25)}
  ]

  def start_link(args) do
    name = args[:name] || __MODULE__
    GenServer.start_link(__MODULE__, args, name: name)
  end

  def init(args) do
    config = Keyword.get(args, :config, @defaults)
    :erlang.system_monitor(self(), config)

    {:ok, []}
  end

  def handle_info({:monitor, pid, _type, _meta} = msg, state) when is_pid(pid) do
    log_process_info(msg, pid)
    {:noreply, state}
  end

  def handle_info(msg, state) do
    Logger.warning("#{__MODULE__} message: " <> inspect(msg))
    {:noreply, state}
  end

  defp log_process_info({:monitor, pid, type, meta} = msg, pid) do
    pid_info =
      pid
      |> Process.info(:dictionary)
      |> case do
        {:dictionary, dict} when is_list(dict) ->
          {List.keyfind(dict, :"$initial_call", 0), List.keyfind(dict, :"$ancestors", 0)}

        other ->
          other
      end

    extra_info =
      Process.info(pid, [
        :registered_name,
        :message_queue_len,
        :total_heap_size,
        :current_stacktrace
      ]) || []

    {initial_call, ancestors, process_label} = extract_pid_info(pid_info)
    registered_name = Keyword.get(extra_info, :registered_name)
    message_queue_len = Keyword.get(extra_info, :message_queue_len)
    total_heap_size = Keyword.get(extra_info, :total_heap_size)
    current_stacktrace = Keyword.get(extra_info, :current_stacktrace)

    process_name =
      format_registered_name(registered_name) ||
        format_process_label(process_label) ||
        format_initial_call(initial_call)

    Logger.warning([
      "#{__MODULE__} Alert: #{inspect(type)}\n",
      "PID: #{inspect(pid)}\n",
      "Process: #{process_name}\n",
      "Meta: #{inspect(meta)}\n",
      "Initial call: #{format_initial_call(initial_call)}\n",
      "Ancestors: #{inspect(ancestors)}\n",
      "Message queue length: #{inspect(message_queue_len)}\n",
      "Total heap size: #{format_heap_size(total_heap_size)}\n",
      "Stacktrace:\n",
      format_stacktrace(current_stacktrace)
    ])
  rescue
    _ ->
      Logger.warning("#{__MODULE__} message: " <> inspect(msg))
  end

  defp extract_pid_info({:dictionary, dict}) when is_list(dict) do
    initial_call = List.keyfind(dict, :"$initial_call", 0)
    ancestors = List.keyfind(dict, :"$ancestors", 0)
    process_label = List.keyfind(dict, :"$process_label", 0)

    initial_call_value = if initial_call, do: elem(initial_call, 1), else: nil
    ancestors_value = if ancestors, do: elem(ancestors, 1), else: nil
    process_label_value = if process_label, do: elem(process_label, 1), else: nil

    {initial_call_value, ancestors_value, process_label_value}
  end

  defp extract_pid_info(_), do: {nil, nil, nil}

  defp format_heap_size(words) when is_integer(words) do
    bytes = words * :erlang.system_info(:wordsize)
    mb = bytes / 1_048_576
    "#{Float.round(mb, 2)} MB"
  end

  defp format_heap_size(_), do: "unknown"

  defp format_stacktrace(stacktrace) when is_list(stacktrace) do
    Exception.format_stacktrace(stacktrace)
  end

  defp format_stacktrace(_), do: "unknown"

  defp format_process_label(nil), do: nil
  defp format_process_label(label) when is_binary(label), do: label
  defp format_process_label(label), do: inspect(label)

  defp format_registered_name([]), do: nil
  defp format_registered_name(nil), do: nil
  defp format_registered_name(name), do: inspect(name)

  defp format_initial_call({:supervisor, mod, arity}), do: Exception.format_mfa(mod, :init, arity)
  defp format_initial_call({m, f, a}), do: Exception.format_mfa(m, f, a)
  defp format_initial_call(nil), do: nil
end
