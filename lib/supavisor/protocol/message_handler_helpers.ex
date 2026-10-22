defmodule Supavisor.Protocol.MessageHandlerHelpers do
  @moduledoc """
  Helpers shared by the frontend message handlers that inspect query text.
  """

  require Logger

  alias Supavisor.PgParser

  # Parse time grows with the query's token count, up to about 1.5 ms at this
  # size for expression-heavy queries. Leaking statements are short, so larger
  # queries are passed through unchecked.
  @max_parsed_query_size 4096

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
    case PgParser.parse(query) do
      {:ok, _parsed} = ok ->
        ok

      {:error, :too_complex} ->
        Logger.warning(
          "skipped transaction mode checks for query with long runs of operator characters"
        )

        :too_complex

      {:error, error} ->
        Logger.debug("Failed to parse query: #{inspect(error)}, query: #{inspect(query)}")
        :unparseable
    end
  end
end
