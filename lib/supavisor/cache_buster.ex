defmodule Supavisor.CacheBuster do
  @moduledoc false

  use Postgrex.ReplicationConnection
  require Logger
  alias Supavisor.Protocol.WalDecoder.Decoder

  alias Decoder.Messages.{
    Relation,
    Update,
    Delete
  }

  def start_link(args) do
    opts =
      Application.get_env(:supavisor, Supavisor.Repo)[:url]
      |> Ecto.Repo.Supervisor.parse_url()

    Postgrex.ReplicationConnection.start_link(__MODULE__, args, opts)
  end

  @spec stop(pid) :: :ok
  def stop(pid) do
    GenServer.stop(pid)
  end

  @impl true
  def init(_args) do
    slot_name = Application.get_env(:supavisor, :cache_repl_slot)

    state = %{
      publication: Application.get_env(:supavisor, :cache_publ_name),
      slot: slot_name <> "#{:erlang.phash2(node())}",
      rels: %{},
      step: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_connect(state) do
    query = "CREATE_REPLICATION_SLOT #{state.slot} TEMPORARY LOGICAL pgoutput NOEXPORT_SNAPSHOT"
    {:query, query, %{state | step: :create_slot}}
  end

  @impl true
  def handle_result(results, %{step: :create_slot} = state)
      when is_list(results) do
    Logger.info("Replication slot created: #{inspect(results)}")

    query =
      "START_REPLICATION SLOT #{state.slot} LOGICAL 0/0 (proto_version '1', publication_names '#{state.publication}')"

    {:stream, query, [], %{state | step: :streaming}}
  end

  def handle_result(results, state) do
    Logger.error("Replication is failed: #{inspect(results)}")
    {:noreply, state}
  end

  @impl true
  def handle_data(<<?w, _header::192, msg::binary>>, state) do
    new_state =
      Decoder.decode_message(msg)
      |> process_message(state)

    {:noreply, new_state}
  end

  # keepalive
  def handle_data(<<?k, _::128, 0>>, state) do
    {:noreply, [], state}
  end

  def handle_data(<<?k, wal_end::64, _::64, 1>>, state) do
    messages = [
      <<?r, wal_end + 1::64, wal_end + 1::64, wal_end + 1::64, current_time()::64, 0>>
    ]

    {:noreply, messages, state}
  end

  def handle_data(data, state) do
    Logger.error("Unknown data: #{inspect(data)}")
    {:noreply, state}
  end

  defp process_message(%Relation{id: id, columns: columns, namespace: schema, name: table}, state) do
    columns =
      Enum.map(columns, fn %{name: name, type: type} ->
        %{name: name, type: type}
      end)

    put_in(state, [:rels, id], {columns, schema, table})
  end

  defp process_message(%Update{} = msg, state) do
    drop_cache(msg, state.rels[msg.relation_id])
    state
  end

  defp process_message(%Delete{} = msg, state) do
    drop_cache(msg, state.rels[msg.relation_id])
    state
  end

  defp process_message(_msg, state) do
    state
  end

  def drop_cache(msg, relation) do
    Logger.debug("Got message: #{inspect(msg)}")
    {columns, _schema, table} = relation

    record = data_tuple_to_map(columns, msg.old_tuple_data)

    tenant =
      if table == "tenants" do
        record["external_id"]
      else
        record["tenant_external_id"]
      end

    Logger.warning("Got update for tenant: #{inspect(tenant)}")

    Supavisor.dirty_terminate(tenant)
  end

  ## Internal functions

  defp data_tuple_to_map(column, tuple_data) do
    column
    |> Enum.with_index()
    |> Enum.reduce_while(%{}, fn {column_map, index}, acc ->
      case column_map do
        %{name: column_name, type: column_type}
        when is_binary(column_name) and is_binary(column_type) ->
          try do
            {:ok, elem(tuple_data, index)}
          rescue
            ArgumentError -> :error
          end
          |> case do
            {:ok, record} ->
              {:cont,
               Map.put(
                 acc,
                 column_name,
                 record
               )}

            :error ->
              {:halt, acc}
          end

        _ ->
          {:cont, acc}
      end
    end)
  end

  @epoch DateTime.to_unix(~U[2000-01-01 00:00:00Z], :microsecond)
  defp current_time(), do: System.os_time(:microsecond) - @epoch
end
