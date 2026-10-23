defmodule Supavisor.Protocol.MessageHandlerHelpers do
  @moduledoc """
  Helpers shared by the frontend message handlers that inspect query text.
  """

  require Logger

  alias Supavisor.PgParser

  # Parse time grows with the query's token count, up to about 0.7 ms at 512
  # bytes and 1.3 ms at 1 KB for expression-heavy queries. Larger queries are
  # parsed on a dirty CPU scheduler. Leaking statements are short, so queries
  # over 1 KB are passed through unchecked.
  @max_normal_parse_size 512
  @max_parsed_query_size 1024

  @spec parse_query(binary()) ::
          {:ok, PgParser.parsed()} | :unparseable | :too_large | :too_complex
  def parse_query(query) when byte_size(query) > @max_parsed_query_size do
    Logger.warning(
      "skipped transaction mode checks for query of #{byte_size(query)} bytes, " <>
        "larger than the #{@max_parsed_query_size} byte limit"
    )

    :too_large
  end

  def parse_query(query) do
    case parse(query) do
      {:ok, _parsed} = ok ->
        ok

      {:error, :too_complex} ->
        Logger.warning(
          "skipped transaction mode checks for query with long runs of operator characters"
        )

        :too_complex

      {:error, :invalid_utf8} ->
        Logger.warning(
          "skipped transaction mode checks for query that is not valid UTF-8, " <>
            "client_encoding other than UTF8 is not supported"
        )

        :unparseable

      {:error, error} ->
        Logger.debug("Failed to parse query: #{inspect(error)}, query: #{inspect(query)}")
        :unparseable
    end
  end

  defp parse(query) when byte_size(query) > @max_normal_parse_size,
    do: PgParser.parse_dirty(query)

  defp parse(query), do: PgParser.parse(query)
end
