defmodule Supavisor.Protocol.FrontendMessageHandler do
  @moduledoc """
  Handles PostgreSQL frontend messages.

  - Parse (P), Bind (B), Close (C), Describe (D): PreparedStatements
  - Simple Query (Q), Sync (S), FunctionCall (F): forwarded unchanged

  Simple queries are first checked by SetStatements and SimpleQueryHandler,
  which reject session-level SET and prepared statement commands when the
  tenant has those checks enabled.

  It also counts the number of messages that produce a `ReadyForQuery` response from the backend.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  require Logger

  alias Supavisor.PgParser
  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.SetStatements
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
  def handle_message(state, ?Q, len, payload) do
    with :ok <- check_simple_query(state, payload) do
      do_handle_message(state, ?Q, len, payload)
    end
  end

  def handle_message(state, tag, len, payload) do
    with :ok <- SetStatements.check(state.set_statements_action, tag, payload) do
      do_handle_message(state, tag, len, payload)
    end
  end

  # Both checks below need the query parsed, and parsing dominates their cost,
  # so parse at most once and let each of them walk the resulting tree.
  defp check_simple_query(state, payload) do
    set_action = state.set_statements_action
    set_check? = set_action not in [nil, :ignore]
    prepare_check? = state.translate? and state.check_simple_query_prepare?

    if set_check? or prepare_check? do
      # Some clients send null terminators
      query = String.trim_trailing(payload, <<0>>)
      parsed = parse_query(query)

      with :ok <- SetStatements.check_parsed(set_action, parsed, query) do
        SimpleQueryHandler.check(prepare_check?, parsed)
      end
    else
      :ok
    end
  end

  defp parse_query(query) do
    case PgParser.parse(query) do
      {:ok, parsed} ->
        parsed

      {:error, error} ->
        Logger.debug("Failed to parse simple query: #{inspect(error)}, query: #{inspect(query)}")
        nil
    end
  end

  defp do_handle_message(%{translate?: false} = state, tag, len, payload) do
    {:ok, count_rfq_producer(state, tag), <<tag, len::32, payload::binary>>}
  end

  defp do_handle_message(state, tag, len, payload) do
    case tag do
      ?P ->
        PreparedStatements.handle_parse_message(state.prepared_statements, len, payload)

      ?B ->
        PreparedStatements.handle_bind_message(state.prepared_statements, len, payload)

      ?C ->
        PreparedStatements.handle_close_message(state.prepared_statements, len, payload)

      ?D ->
        PreparedStatements.handle_describe_message(state.prepared_statements, len, payload)

      tag when tag in [?Q, ?S, ?F] ->
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
