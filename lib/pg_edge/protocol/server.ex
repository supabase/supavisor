defmodule PgEdge.Protocol.Server do
  require Logger

  @pkt_header_size 5

  defmodule(Pkt,
    do: defstruct([:tag, :len, :payload])
  )

  def decode(data) do
    decode(data, [])
  end

  def decode(data, acc) when byte_size(data) >= @pkt_header_size do
    {:ok, pkt, rest} = decode_pkt(data)
    decode(rest, [pkt | acc])
  end

  def decode(_, acc) do
    Enum.reverse(acc)
  end

  def packet(tag, pkt_len, payload) do
    %Pkt{
      tag: tag,
      len: pkt_len + 1,
      payload: decode_payload(tag, payload)
    }
  end

  def decode_pkt(<<char::integer-8, pkt_len::integer-32, rest::binary>>, decode_payload \\ true) do
    tag = tag(char)
    payload_len = pkt_len - 4

    <<bin_payload::binary-size(payload_len), rest2::binary>> = rest

    payload =
      if decode_payload do
        decode_payload(tag, bin_payload)
      else
        nil
      end

    {:ok, %Pkt{tag: tag, len: pkt_len + 1, payload: payload}, rest2}
  end

  def tag(char) do
    case char do
      ?R -> :authentication
      ?K -> :backend_key_data
      ?2 -> :bind_complete
      ?3 -> :close_complete
      ?C -> :command_complete
      ?d -> :copy_data
      ?c -> :copy_done
      ?G -> :copy_in_response
      ?H -> :copy_out_response
      ?W -> :copy_both_response
      ?D -> :data_row
      ?I -> :empty_query_response
      ?E -> :error_response
      ?V -> :function_call_response
      ?n -> :no_data
      ?N -> :notice_response
      ?A -> :notification_response
      ?t -> :parameter_description
      ?S -> :parameter_status
      ?1 -> :parse_complete
      ?s -> :portal_suspended
      ?Z -> :ready_for_query
      ?T -> :row_description
      _ -> :undefined
    end
  end

  def decode_payload(:authentication, payload) do
    case payload do
      <<0::integer-32>> ->
        :authentication_ok

      <<2::integer-32>> ->
        :authentication_kerberos_v5

      <<3::integer-32>> ->
        :authentication_cleartext_password

      <<5::integer-32, salt::binary-4>> ->
        {:authentication_md5_password, salt}

      <<6::integer-32>> ->
        :authentication_scm_credential

      <<7::integer-32>> ->
        :authentication_gss

      <<8::integer-32, rest::binary>> ->
        {:authentication_gss_continue, rest}

      <<9::integer-32>> ->
        :authentication_sspi

      <<10::integer-32, methods_b::binary>> ->
        {:authentication_sasl_password, methods_b}

      <<11::integer-32, server_first::binary>> ->
        {:authentication_server_first_message, server_first}

      <<12::integer-32, server_final_msg::binary>> ->
        {:authentication_server_final_message, server_final_msg}

      other ->
        {:undefined, other}
    end
  end

  def decode_payload(:parameter_status, payload) do
    case String.split(payload, <<0>>, trim: true) do
      [k, v] -> {k, v}
      _ -> :undefined
    end
  end

  def decode_payload(:backend_key_data, <<proc_id::integer-32, secret::integer-32>>) do
    %{procid: proc_id, secret: secret}
  end

  def decode_payload(:ready_for_query, payload) do
    case payload do
      <<"I">> -> :idle
      <<"T">> -> :transaction
      <<"E">> -> :error
    end
  end

  def decode_payload(:parse_complete, "") do
    :parse_complete
  end

  def decode_payload(:parameter_description, <<count::integer-16, rest::binary>>) do
    {count, decode_parameter_description(rest, [])}
  end

  def decode_payload(:row_description, <<count::integer-16, rest::binary>>) do
    decode_row_description(count, rest, [])
  end

  def decode_payload(:data_row, payload) do
    # String.split(payload, <<0>>)
    nil
  end

  def decode_payload(:error_response, _payload) do
    :error
  end

  def decode_payload(_, _) do
    :undefined
  end

  def decode_row_description(0, "", acc), do: Enum.reverse(acc)

  def decode_row_description(count, rest, acc) do
    case decode_string(rest) do
      {:ok, field_name,
       <<table_oid::integer-32, attr_num::integer-16, data_type_oid::integer-32,
         data_type_size::integer-16, type_modifier::integer-32, format_code::integer-16,
         tail::binary>>} ->
        case decode_format_code(format_code) do
          {:ok, format} ->
            field = %{
              name: field_name,
              type_info: PgEdge.Protocol.PgType.type(data_type_oid),
              table_oid: table_oid,
              attr_number: attr_num,
              data_type_oid: data_type_oid,
              data_type_size: data_type_size,
              type_modifier: type_modifier,
              format: format
            }

            decode_row_description(count - 1, tail, [field | acc])
        end

      _ ->
        {:error, :decode}
    end
  end

  def decode_format_code(0) do
    {:ok, :text}
  end

  def decode_format_code(1) do
    {:ok, :binary}
  end

  def decode_format_code(_) do
    {:error, :unknown_format_code}
  end

  def decode_string(bin) do
    case :binary.match(bin, <<0>>) do
      :nomatch ->
        {:error, :not_null_terminated}

      {pos, 1} ->
        {string, <<0, rest::binary>>} = :erlang.split_binary(bin, pos)
        {:ok, string, rest}
    end
  end

  def decode_parameter_description("", acc), do: Enum.reverse(acc)

  def decode_parameter_description(<<oid::integer-32, rest::binary>>, acc) do
    decode_parameter_description(rest, [oid | acc])
  end

  def flush() do
    <<?H, 4::integer-32>>
  end

  def sync() do
    <<?S, 4::integer-32>>
  end

  def encode(query) do
    payload = [[], <<0>>, query, <<0>>, <<0, 0>>, []]
    payload_len = IO.iodata_length(payload) + 4
    [<<?P, payload_len::integer-32>>, payload]
  end

  def test_extended_query() do
    [
      encode("select * from todos where id = 40;"),
      [<<68, 0, 0, 0, 6, 83>>, [], <<0>>],
      flush()
    ]
  end
end
