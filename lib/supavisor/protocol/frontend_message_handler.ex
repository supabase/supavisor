defmodule Supavisor.Protocol.FrontendMessageHandler do
  @moduledoc """
  Handles PostgreSQL frontend messages.

  - Parse (P), Bind (B), Close (C), Describe (D): PreparedStatements
  - Simple Query (Q), Sync (S), FunctionCall (F): forwarded unchanged

  Parse (P) and Simple Query (Q) messages are validated before being handled,
  rejecting session-level SET and prepared statement commands when the tenant
  has those checks enabled.

  It also counts the number of messages that produce a `ReadyForQuery` response from the backend.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  alias Supavisor.Protocol.ParseMessageHandler
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
      translate?: true,
      # Tenant's txn_mode_set_action field:
      set_statements_action: :ignore,
      # Rejection of PREPARE/EXECUTE/DEALLOCATE on the simple query protocol.
      # Costs a full parse of every simple query, so it is opt-in via the
      # check_simple_query_prepare feature flag.
      check_simple_query_prepare?: false
    }
  end

  @impl true
  def handle_message(state, tag, len, payload) do
    case {tag, state.translate?} do
      {?P, _translate?} ->
        ParseMessageHandler.handle_message(state, len, payload)

      {?Q, _translate?} ->
        SimpleQueryHandler.handle_message(state, len, payload)

      {?B, true} ->
        PreparedStatements.handle_bind_message(state.prepared_statements, len, payload)

      {?C, true} ->
        PreparedStatements.handle_close_message(state.prepared_statements, len, payload)

      {?D, true} ->
        PreparedStatements.handle_describe_message(state.prepared_statements, len, payload)

      {_tag, _translate?} ->
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
