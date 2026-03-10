defmodule Supavisor.Protocol.StartupOptions do
  @moduledoc """
  Parses the PostgreSQL `options` startup parameter.

  The `options` field in a StartupMessage contains a single string with
  command-line arguments. This module tokenizes that string (respecting
  backslash escapes per `pg_split_opts`) and extracts `-c name=value`
  and `--name=value` GUC settings into a map.
  """

  # All characters matched by C's isspace(): space, tab, newline,
  # carriage return, vertical tab, form feed.
  @whitespace [?\s, ?\t, ?\n, ?\r, ?\v, ?\f]
  @escape_targets ["\\", " ", "\t", "\n", "\r", "\v", "\f"]

  @doc """
  Parses a PostgreSQL startup `options` string into a map of GUC settings.

  ## Examples

      iex> Supavisor.Protocol.StartupOptions.parse("-c search_path=public -c work_mem=64MB")
      %{"search_path" => "public", "work_mem" => "64MB"}

      iex> Supavisor.Protocol.StartupOptions.parse("--search_path=public")
      %{"search_path" => "public"}

  """
  @spec parse(String.t()) :: map()
  def parse(str) do
    str
    |> tokenize()
    |> parse_tokens(%{})
  end

  # Tokenize by whitespace, handling backslash escapes
  # per pg_split_opts (src/backend/utils/init/postinit.c:497).
  #
  # - Backslash followed by any char => literal char (backslash consumed)
  # - Trailing backslash => consumed silently
  defp tokenize(str), do: tokenize(str, [], [])

  defp tokenize(<<>>, [], acc), do: Enum.reverse(acc)

  defp tokenize(<<>>, current, acc),
    do: Enum.reverse([current |> Enum.reverse() |> IO.iodata_to_binary() | acc])

  defp tokenize(<<c, rest::binary>>, [], acc) when c in @whitespace,
    do: tokenize(rest, [], acc)

  defp tokenize(<<c, rest::binary>>, current, acc) when c in @whitespace do
    token = current |> Enum.reverse() |> IO.iodata_to_binary()
    tokenize(rest, [], [token | acc])
  end

  # Trailing backslash: consumed, nothing appended (per pg_split_opts)
  defp tokenize(<<?\\>>, current, acc), do: tokenize(<<>>, current, acc)

  defp tokenize(<<?\\, c, rest::binary>>, current, acc),
    do: tokenize(rest, [<<c>> | current], acc)

  defp tokenize(<<c, rest::binary>>, current, acc),
    do: tokenize(rest, [<<c>> | current], acc)

  # Parse tokens into key-value pairs.
  # Supports: -c name=value, --name=value
  defp parse_tokens([], acc), do: acc

  defp parse_tokens(["-c", pair | rest], acc) do
    case String.split(pair, "=", parts: 2) do
      [name, value] -> parse_tokens(rest, Map.put(acc, name, value))
      _ -> parse_tokens(rest, acc)
    end
  end

  defp parse_tokens(["--" <> pair | rest], acc) do
    case String.split(pair, "=", parts: 2) do
      [name, value] -> parse_tokens(rest, Map.put(acc, name, value))
      _ -> parse_tokens(rest, acc)
    end
  end

  # Skip unrecognized tokens
  defp parse_tokens([_ | rest], acc), do: parse_tokens(rest, acc)

  @doc """
  Encodes a map of GUC settings into a PostgreSQL startup `options` string.

  All `isspace()` characters and backslashes in values are backslash-escaped per `pg_split_opts`.

  ## Examples

      iex> Supavisor.Protocol.StartupOptions.encode(%{"search_path" => "public"})
      "--search_path=public"

      iex> Supavisor.Protocol.StartupOptions.encode(%{"search_path" => "schemaA, schemaB"})
      "--search_path=schemaA,\\\\ schemaB"

  """
  @spec encode(map()) :: String.t()
  def encode(opts) when opts == %{}, do: ""

  def encode(opts) do
    Enum.map_join(opts, " ", fn {name, value} -> "--#{name}=#{escape_value(value)}" end)
  end

  defp escape_value(value) do
    :binary.replace(value, @escape_targets, <<"\\">>, [:global, {:insert_replaced, 1}])
  end
end
