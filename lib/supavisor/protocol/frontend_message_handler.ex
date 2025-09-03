defmodule Supavisor.Protocol.FrontendMessageHandler do
  @moduledoc """
  Handles PostgreSQL frontend messages.

  - Parse (P), Bind (B), Close (C), Describe (D): PreparedStatements
  - Simple Query (Q): SimpleQueryHandler
  """

  @behaviour Supavisor.Protocol.MessageHandler

  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.SimpleQueryHandler

  @impl true
  def handled_message_types, do: [?P, ?B, ?C, ?D, ?Q]

  @impl true
  def init_state do
    %{
      prepared_statements: PreparedStatements.init_storage()
    }
  end

  @impl true
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
    end
    |> case do
      {:ok, new_ps_state, result} ->
        new_state = %{state | prepared_statements: new_ps_state}
        {:ok, new_state, result}

      error ->
        error
    end
  end
end
