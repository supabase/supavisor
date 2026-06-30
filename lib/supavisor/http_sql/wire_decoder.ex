defmodule Supavisor.HttpSql.WireDecoder do
  @moduledoc """
  Decodes a buffer of backend wire bytes received from the upstream PostgreSQL
  connection (via `{:proc, pid}` `:db_bytes` messages) into structured results
  consumable by the HTTP /sql response builder.

  The single public entry point `parse_execute_response/1` consumes
  ParseComplete + BindComplete + (RowDescription)? + DataRow* +
  CommandComplete + ReadyForQuery and returns the row set. It stops on an
  `ErrorResponse`, returning `{:error, %PgError{}}`. `Notice` responses are
  ignored. Reuses `Supavisor.Protocol.Server.decode/1` for framing and tag
  mapping.
  """

  alias Supavisor.HttpSql.PgError
  alias Supavisor.Protocol.Server

  @type oid :: pos_integer()
  @type column :: %{name: String.t(), oid: oid()}
  @type row :: [binary() | nil]

  @type execute_result :: %{
          required(:columns) => [column()] | nil,
          required(:rows) => [row()],
          required(:command) => String.t() | nil,
          required(:num_rows) => non_neg_integer()
        }

  @spec parse_execute_response(binary()) ::
          {:ok, execute_result()} | {:error, PgError.t() | :incomplete | :unexpected}
  def parse_execute_response(bin) when is_binary(bin) do
    with {:ok, pkts, _rest} <- decode(bin) do
      walk_execute(pkts, %{columns: nil, rows: [], command: nil, num_rows: 0})
    end
  end

  @doc """
  Returns `true` when the buffer ends with a complete `ReadyForQuery`
  packet. The receive loop calls this after each `:db_bytes` chunk to
  decide whether to stop accumulating.

  ## Why we don't just substring-match on `<<?Z, 5::32>>`

  A `DataRow` column whose text value happens to contain the byte
  sequence `Z\\x00\\x00\\x00\\x05` (BYTEA hex dumps, certain text
  payloads, JSON containing `Z` + 4 zero bytes + `0x05`) would false-
  positive a substring scan and make the receive loop return a
  truncated buffer. Instead we frame the buffer with
  `Supavisor.Protocol.Server.decode/1` and check whether the last fully
  decoded packet is `ready_for_query`.
  """
  @spec ready_for_query?(binary()) :: boolean()
  def ready_for_query?(bin) when is_binary(bin) do
    case safe_decode(bin) do
      {:ok, pkts, <<>>} ->
        match?(%{tag: :ready_for_query}, List.last(pkts))

      _ ->
        false
    end
  end

  # ---------------------------------------------------------------------------

  defp decode(bin) do
    case safe_decode(bin) do
      {:ok, pkts, <<>>} -> {:ok, pkts, <<>>}
      {:ok, _pkts, _rest} -> {:error, :incomplete}
      {:error, _} = err -> err
    end
  end

  # `Supavisor.Protocol.Server.decode/1` may raise on malformed input
  # (e.g. a packet header whose declared length is < 4, producing a
  # negative `binary-size`). Wrap it so callers always get a tagged tuple.
  defp safe_decode(bin) do
    {:ok, pkts, rest} = Server.decode(bin)
    {:ok, pkts, rest}
  rescue
    e -> {:error, {:bad_packet, e}}
  end

  defp walk_execute([], acc), do: {:ok, acc}

  defp walk_execute([%{tag: :bind_complete} | rest], acc), do: walk_execute(rest, acc)

  defp walk_execute([%{tag: :parse_complete} | rest], acc), do: walk_execute(rest, acc)

  defp walk_execute([%{tag: :row_description, payload: fields} | rest], acc) when is_list(fields),
    do: walk_execute(rest, %{acc | columns: to_columns(fields)})

  defp walk_execute([%{tag: :no_data} | rest], acc), do: walk_execute(rest, acc)

  defp walk_execute([%{tag: :data_row, bin: bin} | rest], acc) do
    row = decode_data_row(bin)
    walk_execute(rest, %{acc | rows: [row | acc.rows]})
  end

  defp walk_execute([%{tag: :command_complete, bin: bin} | rest], acc) do
    {tag, n} = parse_command_complete(bin)
    walk_execute(rest, %{acc | command: tag, num_rows: n})
  end

  defp walk_execute([%{tag: :notice_response} | rest], acc), do: walk_execute(rest, acc)

  defp walk_execute([%{tag: :empty_query_response} | rest], acc),
    do: walk_execute(rest, %{acc | command: "", num_rows: 0})

  defp walk_execute([%{tag: :portal_suspended} | rest], acc), do: walk_execute(rest, acc)

  defp walk_execute([%{tag: :ready_for_query} | _], acc),
    do: {:ok, %{acc | rows: Enum.reverse(acc.rows)}}

  defp walk_execute([%{tag: :error_response, payload: fields} | _], _acc) when is_map(fields),
    do: {:error, PgError.exception(fields)}

  defp walk_execute([_unexpected | rest], acc), do: walk_execute(rest, acc)

  defp to_columns(fields) do
    Enum.map(fields, fn f -> %{name: f.name, oid: f.data_type_oid} end)
  end

  # Strips the 1-byte tag and 4-byte length header, then parses the body:
  #   Int16(column_count) + [Int32(len) + Byte_n_(value)]×N
  # A length of -1 means SQL NULL with no value bytes.
  defp decode_data_row(<<?D, _len::32, count::16, rest::binary>>) do
    decode_data_row_cols(count, rest, [])
  end

  defp decode_data_row_cols(0, _, acc), do: Enum.reverse(acc)

  defp decode_data_row_cols(n, <<-1::32-signed, rest::binary>>, acc),
    do: decode_data_row_cols(n - 1, rest, [nil | acc])

  defp decode_data_row_cols(n, <<size::32-signed, val::binary-size(size), rest::binary>>, acc),
    do: decode_data_row_cols(n - 1, rest, [val | acc])

  # CommandComplete payload is a null-terminated string. Row-count-bearing
  # commands carry the count as the last token; multi-word DDL commands
  # like `CREATE TABLE` or `ALTER INDEX` don't.
  #
  # Shape per PG protocol docs:
  #
  #   * `INSERT 0 <n>`            — INSERT (legacy OID + row count)
  #   * `MERGE 0 0 0 <n>`         — MERGE (PG17+)
  #   * `<VERB> <n>`              — SELECT, UPDATE, DELETE, COPY, FETCH, MOVE
  #   * `<VERB>`                  — BEGIN, COMMIT, ROLLBACK, SET, ...
  #   * `<VERB> <NOUN>...`        — CREATE TABLE, DROP INDEX, ALTER VIEW, ...
  #
  # The two-token case is ambiguous (`UPDATE 5` vs `CREATE TABLE`); we
  # disambiguate by trying to parse the last token as an integer.
  defp parse_command_complete(<<?C, _len::32, payload::binary>>) do
    string =
      case :binary.split(payload, <<0>>) do
        [s, _] -> s
        [s] -> s
      end

    case String.split(string, " ", trim: true) do
      ["INSERT", _oid, n] ->
        {"INSERT", parse_int(n)}

      ["MERGE", _ins, _upd, _del, n] ->
        {"MERGE", parse_int(n)}

      [tag] ->
        {tag, 0}

      tokens ->
        # If the last token parses as an integer, the rest is the verb
        # phrase. Otherwise the whole string is the verb (multi-word DDL).
        last = List.last(tokens)

        case Integer.parse(last) do
          {n, ""} ->
            verb = tokens |> Enum.drop(-1) |> Enum.join(" ")
            {verb, n}

          _ ->
            {Enum.join(tokens, " "), 0}
        end
    end
  end

  defp parse_int(s) do
    case Integer.parse(s) do
      {n, ""} -> n
      _ -> 0
    end
  end
end
