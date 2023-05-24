defmodule Supavisor.CDC do
  @moduledoc """
  Change Data Capture from PostgreSQL queries.
  """

  require Logger

  alias Supavisor.CDC.{Change, Error, State}
  alias Supavisor.Protocol.Client
  alias Supavisor.Protocol.Server

  @writer_module Application.compile_env!(:supavisor, :writer_module)
  @set_sync_user Client.encode(:query, ~s(set "sync.user" to 'sequin_proxy'))

  def init(db_namespace) do
    %State{db_namespace: db_namespace}
  end

  def reset(%State{} = state) do
    %State{db_namespace: state.db_namespace}
  end

  def change(bin, %State{in_transaction?: false} = state) do
    state = %{state | client_packets: [bin | state.client_packets]}

    if begin?(bin) do
      Logger.debug("change/2 found begin;")
      bin = prepend_sync_user(bin)
      {:ok, bin, %{state | in_transaction?: true}}
    else
      Logger.debug("change/2 found no begin;")
      wrapped_bin = wrap(bin, state.db_namespace)
      {:ok, wrapped_bin, state}
    end
  end

  def change(bin, %State{in_transaction?: true} = state) do
    state = %{state | client_packets: [bin | state.client_packets]}

    case Client.decode(bin) do
      [%Client.Pkt{tag: :query, payload: "commit;"}] ->
        Logger.debug("change/2 found commit;")

        {:ok, select_cdc_and_rollback(state.db_namespace), %{state | in_transaction?: false}}

      [%Client.Pkt{tag: :query, payload: "rollback;"}] ->
        Logger.debug("change/2 found rollback;")

        {:ok, rollback(), %{state | in_transaction?: false}}

      [decoded_bin] ->
        Logger.debug("change/2 found decoded_bin: #{inspect(decoded_bin, pretty: true)}")
        {:ok, bin, state}
    end
  end

  def capture(%State{} = state, tenant) do
    state.server_packets
    |> Enum.reverse()
    |> Enum.join()
    |> Server.decode()
    |> Enum.map(fn
      %Server.Pkt{tag: :data_row, payload: ["_sync_cdc" | values]} -> values
      _ -> nil
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.map(fn [_id, table_name, operation, changes, transaction_id, inserted_at] ->
      %Change{
        table_name: table_name,
        operation: operation(operation),
        payload: Jason.decode!(changes),
        transaction_id: transaction_id,
        inserted_at: inserted_at
      }
    end)
    |> case do
      [] ->
        # TODO: Return only `commit` or `rollback` for transactions
        Logger.debug("capture/1 found no changes;")
        query = state.client_packets |> Enum.reverse() |> Enum.join()
        {:ok, query}

      changed_packets ->
        handle_changed_packets(changed_packets, tenant)
    end
  end

  defp handle_changed_packets(changed_packets, tenant) do
    case @writer_module.handle_changes(changed_packets, tenant) do
      {:ok, changed_ids} ->
        changed_ids = Enum.map_join(changed_ids, ", ", &"'#{&1}'")
        query = "SELECT unnest(ARRAY[#{changed_ids}]::TEXT[]) AS changed_ids;"
        {:ok, Client.encode(:query, query)}

      {:error, %Error{} = error} ->
        {:error, Client.encode(error)}
    end
  end

  def should_forward_to_client?(%State{in_transaction?: in_transaction?}), do: in_transaction?

  def received_server_packets(%State{} = state, server_packets) do
    %{state | server_packets: [server_packets | state.server_packets]}
  end

  defp prepend_sync_user(bin) do
    <<@set_sync_user::binary, bin::binary>>
  end

  defp wrap(bin, db_namespace) do
    begin = Client.encode(:query, "begin;")
    cdc = Client.encode(:query, "select '_sync_cdc', * from #{db_namespace}._sync_cdc;")
    rollback = Client.encode(:query, "rollback;")

    <<begin::binary, @set_sync_user::binary, bin::binary, cdc::binary, rollback::binary>>
  end

  defp begin?(bin) do
    case Client.decode(bin) do
      [%Client.Pkt{tag: :query, payload: "begin;"}] -> true
      [_] -> false
    end
  end

  defp select_cdc_and_rollback(db_namespace) do
    cdc = Client.encode(:query, "select '_sync_cdc', * from #{db_namespace}._sync_cdc;")
    rollback = Client.encode(:query, "rollback;")

    <<cdc::binary, rollback::binary>>
  end

  defp rollback do
    rollback = Client.encode(:query, "rollback;")

    <<rollback::binary>>
  end

  @spec operation(String.t()) :: Change.operation()
  defp operation("insert"), do: :insert
  defp operation("update"), do: :update
  defp operation("delete"), do: :delete
end
