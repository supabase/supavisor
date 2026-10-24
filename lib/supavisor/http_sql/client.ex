defmodule Supavisor.HttpSql.Client do
  @moduledoc """
  Runs the queries of an HTTP request as a regular client of Supavisor.

  All the queries are sent at once, followed by a single Sync. A transaction
  left open or aborted is rolled back before the connection is closed.
  """

  alias Supavisor.HttpSql
  alias Supavisor.Protocol.Server
  alias Supavisor.Protocol.StartupOptions

  @spec run(HttpSql.conn_info(), String.t(), [HttpSql.query()]) ::
          {:ok, [HttpSql.result()]} | {:error, {:postgres, map()} | term()}
  def run(conn_info, client_ip, queries) do
    port = internal_port(conn_info)
    max_bytes = Application.get_env(:supavisor, :http_sql_max_response_bytes, 10 * 1024 * 1024)

    case :gen_tcp.connect(~c"localhost", port, [:binary, packet: :raw, active: false]) do
      {:ok, sock} ->
        conn = %{sock: sock, buffer: <<>>, budget: max_bytes}

        try do
          with {:ok, conn} <- startup(conn, conn_info, client_ip),
               {:ok, conn} <- send_queries(conn, queries) do
            case receive_results(conn, length(queries)) do
              {:error, :response_too_large} -> {:error, {:response_too_large, max_bytes}}
              result -> result
            end
          end
        after
          :gen_tcp.send(sock, <<?X, 4::32>>)
          :gen_tcp.close(sock)
        end

      {:error, reason} ->
        {:error, {:connect, reason}}
    end
  end

  defp internal_port(conn_info) do
    ports = Application.fetch_env!(:supavisor, :transaction_proxy_ports)
    shard = :erlang.phash2({conn_info.user, conn_info.database}, length(ports))
    :ranch.get_port({:pg_proxy_internal, :transaction, shard})
  end

  ## Startup

  defp startup(conn, conn_info, client_ip) do
    # `client_tls` is set to always true to force cleartext authentication (the conn is local anyway).
    options =
      Map.merge(conn_info.options, %{
        "client_ip" => client_ip,
        "client_tls" => "true"
      })

    params =
      [
        {"user", conn_info.user},
        {"database", conn_info.database},
        {"application_name", conn_info.application_name},
        {"options", StartupOptions.encode(options)}
      ]
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)

    with :ok <- sock_send(conn, :pgo_protocol.encode_startup_message(params)) do
      authenticate(conn, conn_info)
    end
  end

  # Authenticate as client.
  defp authenticate(conn, conn_info) do
    with {:ok, type, body, conn} <- recv_message(conn) do
      case {type, body} do
        # AuthenticationCleartextPassword
        {?R, <<3::32>>} ->
          with :ok <- sock_send(conn, password_message([conn_info.password, 0])),
               do: authenticate(conn, conn_info)

        # AuthenticationOk
        {?R, <<0::32>>} ->
          authenticate(conn, conn_info)

        # ParameterStatus, BackendKeyData, notices
        {type, _body} when type in [?S, ?K, ?N] ->
          authenticate(conn, conn_info)

        {?Z, _status} ->
          {:ok, conn}

        {?E, body} ->
          {:error, {:postgres, Server.decode_error_response(body)}}

        {type, _body} ->
          {:error, {:unexpected_message, type}}
      end
    end
  end

  defp password_message(payload),
    do: [?p, <<IO.iodata_length(payload) + 4::32>>, payload]

  ## Queries

  defp send_queries(conn, queries) do
    msgs =
      Enum.map(queries, fn {sql, params} ->
        [
          :pgo_protocol.encode_parse_message("", sql, []),
          bind_message(params),
          :pgo_protocol.encode_describe_message(:portal, ""),
          :pgo_protocol.encode_execute_message("", 0)
        ]
      end)

    with :ok <- sock_send(conn, [msgs, :pgo_protocol.encode_sync_message()]), do: {:ok, conn}
  end

  # An unnamed portal for the unnamed statement, with every param and result in text format.
  defp bind_message(params) do
    params =
      Enum.map(params, fn
        nil -> <<-1::32-signed>>
        value -> [<<byte_size(value)::32>>, value]
      end)

    body = [<<0, 0, 0::16, length(params)::16>>, params, <<0::16>>]
    [?B, <<IO.iodata_length(body) + 4::32>>, body]
  end

  defp receive_results(conn, count), do: receive_results(conn, count, [], nil, nil)

  defp receive_results(conn, count, results, current, error) do
    with {:ok, type, body, conn} <- recv_message(conn) do
      case type do
        # ParseComplete
        ?1 ->
          # Each query's responses start with its ParseComplete,
          # so a new one starts the next result.
          results = if current, do: [current | results], else: results
          current = %{fields: [], rows: <<>>, command: nil, row_count: nil}
          receive_results(conn, count, results, current, error)

        # RowDescription
        ?T ->
          current = %{current | fields: decode_fields(body)}
          receive_results(conn, count, results, current, error)

        # DataRow. It's encoded right away and appended to the result's rows binary.
        ?D ->
          row = JSON.encode!(decode_row(body))
          budget = conn.budget - byte_size(row)

          if budget < 0 do
            {:error, :response_too_large}
          else
            rows =
              if current.rows == <<>>, do: row, else: <<current.rows::binary, ?,, row::binary>>

            receive_results(
              %{conn | budget: budget},
              count,
              results,
              %{current | rows: rows},
              error
            )
          end

        # CommandComplete
        ?C ->
          {command, row_count} = decode_command(body)
          current = %{current | command: command, row_count: row_count}
          receive_results(conn, count, results, current, error)

        # ErrorResponse
        ?E ->
          error = error || Server.decode_error_response(body)
          receive_results(conn, count, results, current, error)

        # ReadyForQuery, answering the Sync
        ?Z ->
          # There's no result to finish if the first query failed to parse.
          results = if current, do: [current | results], else: results
          finish_results(conn, count, results, body, error)

        # BindComplete, NoData, EmptyQueryResponse, PortalSuspended, notices, ParameterStatus
        _ ->
          receive_results(conn, count, results, current, error)
      end
    end
  end

  defp finish_results(conn, count, results, status, error) do
    # A query can leave a transaction open, and a failed batch leaves it aborted.
    # It's rolled back, so the pool gets the connection back clean.
    if status != "I", do: rollback(conn)

    cond do
      error -> {:error, {:postgres, error}}
      length(results) == count -> {:ok, Enum.reverse(results)}
      true -> {:error, :unexpected_response}
    end
  end

  defp rollback(conn) do
    with :ok <- sock_send(conn, :pgo_protocol.encode_query_message("ROLLBACK")),
         do: recv_until_ready(conn)
  end

  defp recv_until_ready(conn) do
    with {:ok, type, _body, conn} <- recv_message(conn) do
      if type == ?Z, do: {:ok, conn}, else: recv_until_ready(conn)
    end
  end

  defp decode_fields(<<count::16, rest::binary>>), do: decode_fields(count, rest, [])

  defp decode_fields(0, _rest, acc), do: Enum.reverse(acc)

  defp decode_fields(count, rest, acc) do
    [name, rest] = :binary.split(rest, <<0>>)

    <<table_oid::32, attr_number::16, data_type_oid::32, data_type_size::16-signed,
      type_modifier::32-signed, _format::16, rest::binary>> = rest

    field = %{
      name: name,
      table_oid: table_oid,
      attr_number: attr_number,
      data_type_oid: data_type_oid,
      data_type_size: data_type_size,
      type_modifier: type_modifier
    }

    decode_fields(count - 1, rest, [field | acc])
  end

  defp decode_row(<<count::16, rest::binary>>), do: decode_row(count, rest, [])

  defp decode_row(0, _rest, acc), do: Enum.reverse(acc)

  defp decode_row(count, <<-1::32-signed, rest::binary>>, acc),
    do: decode_row(count - 1, rest, [nil | acc])

  defp decode_row(count, <<size::32, value::binary-size(size), rest::binary>>, acc),
    do: decode_row(count - 1, rest, [value | acc])

  # The command is the tag's first word, and the row count its last one.
  defp decode_command(body) do
    [command | rest] = body |> String.trim_trailing(<<0>>) |> String.split(" ")

    row_count =
      with [_ | _] <- rest,
           {count, ""} <- Integer.parse(List.last(rest)) do
        count
      else
        _ -> nil
      end

    {command, row_count}
  end

  ## Socket

  defp sock_send(conn, data) do
    case :gen_tcp.send(conn.sock, data) do
      :ok -> :ok
      {:error, reason} -> {:error, {:send, reason}}
    end
  end

  # A message that doesn't fit is turned away from its header.
  defp recv_message(%{buffer: <<_type, len::32, _::binary>>, budget: budget})
       when len - 4 > budget,
       do: {:error, :response_too_large}

  # Consume one complete message.
  defp recv_message(%{buffer: <<type, len::32, rest::binary>>} = conn)
       when byte_size(rest) >= len - 4 do
    <<body::binary-size(len - 4), rest::binary>> = rest
    {:ok, type, body, %{conn | buffer: rest}}
  end

  # Once a message's length is known, the rest of it is read at once.
  defp recv_message(%{buffer: <<_type, len::32, rest::binary>>} = conn),
    do: recv_more(conn, len - 4 - byte_size(rest))

  defp recv_message(conn), do: recv_more(conn, 0)

  defp recv_more(conn, length) do
    case :gen_tcp.recv(conn.sock, length) do
      # Appending to an empty buffer would still copy `data`.
      {:ok, data} when conn.buffer == <<>> -> recv_message(%{conn | buffer: data})
      {:ok, data} -> recv_message(%{conn | buffer: conn.buffer <> data})
      {:error, reason} -> {:error, {:recv, reason}}
    end
  end
end
