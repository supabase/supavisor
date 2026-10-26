defmodule Supavisor.Protocol.FrontendMessageHandler do
  @moduledoc """
  Handles PostgreSQL frontend messages.

  - Parse (P), Bind (B), Close (C), Describe (D): PreparedStatements
  - Simple Query (Q), Execute (E), Sync (S), FunctionCall (F), CopyDone (c), CopyFail (f):
    forwarded unchanged

  Parse (P) and Simple Query (Q) messages are validated before being handled,
  rejecting statements that leave session state behind and prepared statement
  commands when the tenant has those checks enabled.

  It also records the messages forwarded in each write, so the DbHandler can follow the
  backend through them (see `Supavisor.Protocol.BackendConnection`). Prepared statement
  packets are recorded as `{:ps, tag}`, since the DbHandler decides what is sent for them.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  alias Supavisor.Protocol.BackendConnection
  alias Supavisor.Protocol.ParseMessageHandler
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
      translate?: true,
      # Tenant's txn_mode_leak_action field:
      leak_action: :ignore,
      # Rejection of PREPARE/EXECUTE/DEALLOCATE on the simple query protocol.
      # Costs a full parse of every simple query, so it is opt-in via the
      # check_simple_query_prepare feature flag.
      check_simple_query_prepare?: false
    }
  end

  @doc """
  Returns the messages forwarded since the last call, in order, and clears them.
  """
  @spec take_forwarded(map()) :: {[BackendConnection.write_tag()], map()}
  def take_forwarded(state), do: {Enum.reverse(state.forwarded), %{state | forwarded: []}}

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
      {:ok, new_ps_state, pkt} when is_tuple(pkt) ->
        {:ok, record(%{state | prepared_statements: new_ps_state}, {:ps, tag}), pkt}

      {:ok, new_ps_state, pkt} ->
        {:ok, record(%{state | prepared_statements: new_ps_state}, tag), pkt}

      error ->
        error
    end
  end

  defp record(state, tag), do: %{state | forwarded: [tag | state.forwarded]}
end
