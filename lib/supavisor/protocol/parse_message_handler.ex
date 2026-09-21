defmodule Supavisor.Protocol.ParseMessageHandler do
  @moduledoc """
  Handles PostgreSQL Parse (P) messages in transaction mode.

  The query is rejected when it would leave session state on the backend and the
  tenant opted into that check. Otherwise the message goes to
  `Supavisor.Protocol.PreparedStatements` for name translation.

  An unparseable query is passed through for the backend to reject.
  """

  alias Supavisor.Protocol.MessageHandlerHelpers
  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.Storage
  alias Supavisor.Protocol.SessionLeaks

  @spec handle_message(map(), non_neg_integer(), binary()) ::
          {:ok, Storage.t(), PreparedStatements.pkt() | PreparedStatements.handled_pkt()}
          | {:error, term()}
          | {:error, atom(), term()}
  def handle_message(state, len, payload) do
    with :ok <- check_session_leaks(state.leak_action, payload) do
      if state.translate? do
        PreparedStatements.handle_parse_message(state.prepared_statements, len, payload)
      else
        {:ok, state.prepared_statements, <<?P, len::32, payload::binary>>}
      end
    end
  end

  defp check_session_leaks(:ignore, _payload), do: :ok

  defp check_session_leaks(set_action, payload) do
    with [_name, rest] <- :binary.split(payload, <<0>>),
         [query, _] <- :binary.split(rest, <<0>>),
         {:ok, parsed} <- MessageHandlerHelpers.parse_query(query) do
      SessionLeaks.check(set_action, parsed, query)
    else
      _ -> :ok
    end
  end
end
