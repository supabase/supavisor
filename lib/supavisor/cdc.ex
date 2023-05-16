defmodule Supavisor.CDC do
  @moduledoc """
  Change Data Capture from PostgreSQL queries.
  """

  require Logger

  alias Supavisor.CDC.{Change, Error}
  alias Supavisor.Protocol.Client
  alias Supavisor.Protocol.Server

  @writer_module Application.compile_env!(:supavisor, :writer_module)

  def change(bin, false) do
    if begin?(bin) do
      Logger.debug("change(bin, false) found begin;")
      {:ok, bin, true}
    else
      Logger.debug("change(bin, false) found no begin;")
      wrapped_bin = wrap(bin)
      {:ok, wrapped_bin, false}
    end
  end

  def change(bin, true) do
    case Client.decode(bin) do
      [%Client.Pkt{tag: :query, payload: "commit;"}] ->
        Logger.debug("change(bin, true) found commit;")
        {:ok, commit(), false}

      [%Client.Pkt{tag: :query, payload: "rollback;"}] ->
        Logger.debug("change(bin, true) found rollback;")
        {:ok, rollback(), false}

      [decoded_bin] ->
        Logger.debug("change(bin, true) found decoded_bin: #{inspect(decoded_bin, pretty: true)}")
        {:ok, bin, true}
    end
  end

  def capture(bin) do
    captured_pkts =
      bin
      |> Server.decode()
      |> Enum.map(fn
        %Server.Pkt{tag: :data_row, payload: ["_sync_cdc" | values]} -> values
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.map(fn [_id, table, operation, payload] ->
        %Change{
          table: table,
          operation: operation(operation),
          payload: Jason.decode!(payload)
        }
      end)

    case @writer_module.handle_changes(captured_pkts) do
      {:ok, changed_ids} ->
        changed_ids = Enum.map_join(changed_ids, ", ", &"'#{&1}'")
        query = "SELECT unnest(ARRAY[#{changed_ids}]::TEXT[]) AS changed_ids;"
        {:ok, Client.encode_pkt(:query, query)}

      {:error, %Error{} = error} ->
        {:error, Client.encode_error(error)}
    end
  end

  defp wrap(bin) do
    begin = Client.encode_pkt(:query, "begin;")
    cdc = Client.encode_pkt(:query, "select '_sync_cdc', * from salesforce._sync_cdc;")
    rollback = Client.encode_pkt(:query, "rollback;")

    <<begin::binary, bin::binary, cdc::binary, rollback::binary>>
  end

  defp begin?(bin) do
    case Client.decode(bin) do
      [%Client.Pkt{tag: :query, payload: "begin;"}] -> true
      [_] -> false
    end
  end

  defp commit do
    cdc = Client.encode_pkt(:query, "select '_sync_cdc', * from salesforce._sync_cdc;")
    rollback = Client.encode_pkt(:query, "rollback;")

    <<cdc::binary, rollback::binary>>
  end

  defp rollback do
    rollback = Client.encode_pkt(:query, "rollback;")

    <<rollback::binary>>
  end

  @spec operation(String.t()) :: Change.operation()
  defp operation("INSERT"), do: :insert
  defp operation("UPDATE"), do: :update
  defp operation("DELETE"), do: :delete
end
