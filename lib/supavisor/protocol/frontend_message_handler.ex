defmodule Supavisor.Protocol.FrontendMessageHandler do
  @moduledoc """
  Handles PostgreSQL frontend messages.

  - Parse (P), Bind (B), Close (C), Describe (D): PreparedStatements
  - Simple Query (Q): SimpleQueryHandler
  - Sync (S), FunctionCall (F): forwarded unchanged

  It also counts the number of messages that produce a `ReadyForQuery` response from the backend.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.SimpleQueryHandler

  @rfq_producers [?Q, ?S, ?F]

  @impl true
  def handled_message_types, do: [?P, ?B, ?C, ?D, ?Q, ?S, ?F]

  @impl true
  def init_state do
    %{
      prepared_statements: PreparedStatements.init_storage(),
      rfq_producers: 0,
      # Prepared statements feature flag:
      translate?: true
    }
  end

  @impl true
  def handle_message(%{translate?: false} = state, tag, len, payload) do
    {:ok, count_rfq_producer(state, tag), <<tag, len::32, payload::binary>>}
  end

  def handle_message(state, tag, len, payload) do
    case tag do
      ?P ->
        PreparedStatements.handle_parse_message(state.prepared_statements, len, payload)

      ?B ->
        PreparedStatements.handle_bind_message(state.prepared_statements, len, payload)

      ?C ->
        PreparedStatements.handle_close_message(state.prepared_statements, len, payload)

      ?D ->
        PreparedStatements.handle_describe_message(state.prepared_statements, len, payload)

      ?Q ->
        SimpleQueryHandler.handle_simple_query_message(state.prepared_statements, len, payload)

      tag when tag in [?S, ?F] ->
        {:ok, state.prepared_statements, <<tag, len::32, payload::binary>>}
    end
    |> case do
      {:ok, new_ps_state, result} ->
        new_state = %{state | prepared_statements: new_ps_state}
        {:ok, count_rfq_producer(new_state, tag), result}

      error ->
        error
    end
  end

  defp count_rfq_producer(state, tag) when tag in @rfq_producers,
    do: %{state | rfq_producers: state.rfq_producers + 1}

  defp count_rfq_producer(state, _tag), do: state
end
