defmodule Supavisor.Logger.LogflareFormatter do
  @behaviour :logger_formatter

  @moduledoc """
  Logs formatter module that produces JSON output that can be ingested by the Logflare.

  ## Options

  - `context` - keys that will be stored in `context` field of the produced
    metadata object
  - `top_level` - keys that should be duplicated in the top-level object
  """
  @default_context ~w[
      application
      module
      function
      file
      line
      pid
      initial_call
      crash_reason
      registered_name
      domain
      gl
      time
      mfa
    ]a

  @impl true
  def check_config(_), do: :ok

  @impl true
  def format(%{msg: msg, level: level, meta: meta}, opts) do
    context_keys = [Map.get(opts, :context, []) | @default_context]
    {context, meta} = Map.split(meta, context_keys)
    top_level = Map.take(meta, opts[:top_level] || [])
    context = add_vm(context)

    out =
      case format_message(msg, meta) do
        {msg, nil} ->
          %{event_message: msg}

        {msg, report} ->
          %{
            event_message: msg,
            message: normalize_deep(report)
          }
      end

    out =
      out
      |> Map.merge(top_level)
      |> Map.merge(%{
        level: Atom.to_string(level),
        metadata: normalize_deep(Map.put(meta, :context, context)),
        timestamp: context.time
      })

    [JSON.encode_to_iodata!(out), "\n"]
  end

  @spec add_vm(map()) :: map()
  defp add_vm(map), do: Map.put(map, :vm, %{node: node()})

  @spec format_message(
          message,
          :logger.metadata()
        ) :: {:unicode.chardata(), map() | nil}
        when message:
               {:io.format(), [term()]}
               | {:report, :logger.report()}
               | {:string, :unicode.chardata()}
  defp format_message({:string, msg}, _), do: {:unicode.characters_to_binary(msg), nil}

  defp format_message({:report, report}, %{error_logger: _, report_cb: cb} = meta)
       when is_function(cb, 1) do
    {msg, _} = format_message(cb.(report), meta)

    {msg, nil}
  end

  defp format_message({:report, report}, meta) do
    case meta[:report_cb] do
      callback when is_function(callback, 1) ->
        {msg, _} = format_message(callback.(report), meta)

        {msg, Map.new(report)}

      callback when is_function(callback, 2) ->
        msg = callback.(report, %{depth: :unlimited, chars_limit: :unlimited, single_line: false})

        {msg, Map.new(report)}

      _ ->
        map = Map.new(report)

        {do_structured(map), map}
    end
  end

  defp format_message({format, args}, _meta) do
    msg =
      format
      |> Logger.Utils.scan_inspect(args, :infinity)
      |> :io_lib.build_text()
      |> :unicode.characters_to_binary()

    {msg, nil}
  end

  @spec do_structured(map()) :: :unicode.chardata()
  defp do_structured(map) do
    Enum.map_join(map, " ", fn
      {key, value} -> [normalize_key(key), "=", inspect(value)]
    end)
  end

  @spec normalize_key(any()) :: :unicode.chardata()
  defp normalize_key(binary) when is_binary(binary), do: binary
  defp normalize_key(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp normalize_key(other), do: inspect(other)

  @spec normalize_deep(any()) :: any()
  defp normalize_deep(str) when is_binary(str), do: str
  # Squeeze `nil` there for convenience
  defp normalize_deep(bool) when bool in [true, false, nil], do: bool
  defp normalize_deep(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp normalize_deep(num) when is_number(num), do: num

  defp normalize_deep(list) when is_list(list) do
    if List.ascii_printable?(list, 256) do
      List.to_string(list)
    else
      Enum.map(list, &normalize_deep/1)
    end
  end

  defp normalize_deep(%_{} = struct) do
    if JSON.Encoder.impl_for(struct) do
      struct
    else
      struct
      |> Map.from_struct()
      |> normalize_deep()
    end
  end

  defp normalize_deep(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {normalize_key(key), normalize_deep(value)} end)
  end

  defp normalize_deep(tuple) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> Enum.map(&normalize_deep/1)

  defp normalize_deep(ref) when is_reference(ref) or is_pid(ref), do: inspect(ref)
  defp normalize_deep(func) when is_function(func), do: inspect(func)
end
