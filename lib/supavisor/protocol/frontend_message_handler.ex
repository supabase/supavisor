defmodule Supavisor.Protocol.FrontendMessageHandler do
  @moduledoc """
  Handles PostgreSQL frontend messages.

  - Parse (P), Bind (B), Close (C), Describe (D): PreparedStatements
  - Simple Query (Q): SimpleQueryHandler
  - Execute (E), Sync (S), FunctionCall (F), CopyDone (c), CopyFail (f): forwarded unchanged

  It also records the messages forwarded in each write, so the DbHandler can follow the
  backend through them (see `Supavisor.Protocol.BackendMessageHandler`). Prepared statement
  packets are recorded as `:ps`, since the DbHandler decides what is sent for them.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.SimpleQueryHandler

  @impl true
  def handled_message_types, do: [?P, ?B, ?C, ?D, ?E, ?Q, ?S, ?F, ?c, ?f]

  @impl true
  def init_state do
    %{
      prepared_statements: PreparedStatements.init_storage(),
      forwarded: [],
      # Prepared statements feature flag:
      translate?: true
    }
  end

  @doc """
  Returns the messages forwarded since the last call, in order, and clears them.
  """
  def take_forwarded(state), do: {Enum.reverse(state.forwarded), %{state | forwarded: []}}

  @impl true
  def handle_message(%{translate?: false} = state, tag, len, payload) do
    {:ok, record(state, tag), <<tag, len::32, payload::binary>>}
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

      tag when tag in [?E, ?S, ?F, ?c, ?f] ->
        {:ok, state.prepared_statements, <<tag, len::32, payload::binary>>}
    end
    |> case do
      {:ok, new_ps_state, pkt} when is_tuple(pkt) ->
        {:ok, record(%{state | prepared_statements: new_ps_state}, :ps), pkt}

      {:ok, new_ps_state, pkt} ->
        {:ok, record(%{state | prepared_statements: new_ps_state}, tag), pkt}

      error ->
        error
    end
  end

  defp record(state, tag), do: %{state | forwarded: [tag | state.forwarded]}
end
