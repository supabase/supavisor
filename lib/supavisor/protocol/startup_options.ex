defmodule Supavisor.Protocol.StartupOptions do
  @moduledoc """
  Parse the `options` (PGOPTIONS) field from a PostgreSQL startup packet.

  Recognizes `-c key=value`, `-ckey=value`, and `--key=value` forms,
  following PostgreSQL rules for whitespace and backslash escaping.

  Returns a map of option keys to values.

  ## Examples

      iex> Supavisor.Protocol.StartupOptions.parse("--log_level=debug -c search_path=public")
      %{"log_level" => "debug", "search_path" => "public"}
  """

  require Logger

  def parse(options) when is_binary(options) do
    options
    |> String.trim()
    |> then(fn
      "" -> %{}
      trimmed -> trimmed |> split_pg_opts() |> tokens_to_map()
    end)
  end

  def parse(_), do: %{}

  # Tokenizer: split PGOPTIONS into tokens while preserving escapes.
  @spec split_pg_opts(String.t()) :: [String.t()]
  defp split_pg_opts(str) when is_binary(str) do
    do_split_pg_opts(String.to_charlist(str), "", [], false)
  end

  defp do_split_pg_opts([], "", acc, _escape), do: Enum.reverse(acc)
  defp do_split_pg_opts([], current, acc, _escape), do: Enum.reverse([current | acc])

  # Handle backslash escape: next char literal
  defp do_split_pg_opts([?\\ | rest], current, acc, _escape),
    do: do_split_pg_opts(rest, current, acc, true)

  defp do_split_pg_opts([c | rest], current, acc, true),
    do: do_split_pg_opts(rest, current <> "\\" <> <<c>>, acc, false)

  # Whitespace delimiter
  defp do_split_pg_opts([c | rest], current, acc, false) when c in [?\s, ?\t, ?\n, ?\r] do
    if current == "" do
      do_split_pg_opts(rest, "", acc, false)
    else
      do_split_pg_opts(rest, "", [current | acc], false)
    end
  end

  # Regular character
  defp do_split_pg_opts([c | rest], current, acc, false),
    do: do_split_pg_opts(rest, current <> <<c>>, acc, false)

  # Token reducer: handles `-c key` `-ckey` `--key` forms and builds the options map.
  @spec tokens_to_map([String.t()]) :: map()
  defp tokens_to_map(tokens) do
    Enum.reduce(tokens, {nil, %{}}, fn
      "-c", {_, acc} ->
        {:expect_kv, acc}

      <<"--", kv::binary>>, {_, acc} ->
        {nil, maybe_put_kv(acc, kv)}

      <<"-c", kv::binary>>, {_, acc} ->
        {nil, maybe_put_kv(acc, kv)}

      token, {:expect_kv, acc} ->
        {nil, maybe_put_kv(acc, token)}

      token, {_, acc} ->
        Logger.debug("StartupOptions: ignored token #{inspect(token)}")
        {nil, acc}
    end)
    |> elem(1)
  end

  defp maybe_put_kv(acc, kv) do
    case String.split(kv, "=", parts: 2) do
      [key, val] when key != "" and val != "" ->
        Map.put(acc, key, val)

      _ ->
        Logger.debug("StartupOptions: invalid argument #{inspect(kv)}")
        acc
    end
  end
end
