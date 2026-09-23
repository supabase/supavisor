defmodule Supavisor.Protocol.MessageHandlerHelpers do
  @moduledoc """
  Helpers shared by the frontend message handlers that inspect query text.
  """

  require Logger

  alias Supavisor.PgParser

  @spec parse_query(binary()) :: {:ok, PgParser.parsed()} | :unparseable
  def parse_query(query) do
    case PgParser.parse(query) do
      {:ok, _parsed} = ok ->
        ok

      {:error, error} ->
        Logger.debug("Failed to parse query: #{inspect(error)}, query: #{inspect(query)}")
        :unparseable
    end
  end
end
