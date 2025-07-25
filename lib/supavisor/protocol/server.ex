defmodule Supavisor.Protocol.Server do
  @moduledoc """
  The Supavisor.Protocol.Server module is responsible for decoding data received from the PostgreSQL server. It provides several functions to decode payloads from different types of messages.

  Message Formats: https://www.postgresql.org/docs/current/protocol-message-formats.html
  Error codes https://www.postgresql.org/docs/current/errcodes-appendix.html
  """
  require Logger
  alias Supavisor.Protocol.PgType

  @pkt_header_size 5
  @authentication_ok <<?R, 8::32, 0::32>>
  @ready_for_query <<?Z, 5::32, ?I>>
  @ssl_request <<8::32, 1234::16, 5679::16>>
  @scram_request <<?R, 23::32, 10::32, "SCRAM-SHA-256", 0, 0>>
  @msg_cancel_header <<16::32, 1234::16, 5678::16>>
  @application_name <<?S, 31::32, "application_name", 0, "Supavisor", 0>>
  @terminate_message <<?X, 4::32>>
  @flush <<?H, 4::integer-32>>
  @sync <<?S, 4::integer-32>>

  defmodule Pkt do
    @moduledoc "Representing a packet structure with tag, length, and payload fields."
    defstruct([:tag, :len, :payload])

    @type t :: %Pkt{
            tag: atom,
            len: integer,
            payload: any
          }
  end

  defmacro cancel_message(pid, key) do
    quote do
      <<unquote(@msg_cancel_header)::binary, unquote(pid)::32, unquote(key)::32>>
    end
  end

  defmacro ssl_request_message, do: @ssl_request

  @spec decode(iodata()) :: [Pkt.t()]
  def decode(data), do: decode(data, [])

  @spec decode_pkt(binary()) :: {:ok, Pkt.t(), binary()} | {:error, :bad_packet}
  def decode_pkt(<<char::integer-8, pkt_len::integer-32, rest::binary>>) do
    payload_len = pkt_len - 4

    case rest do
      <<bin_payload::binary-size(payload_len), rest2::binary>> ->
        tag = tag(char)
        payload = decode_payload(tag, bin_payload)
        {:ok, %Pkt{tag: tag, len: pkt_len + 1, payload: payload}, rest2}

      _ ->
        {:error, :bad_packet}
    end
  end

  def decode_pkt(_), do: {:error, :bad_packet}

  @spec decode_string(binary()) :: {:ok, binary(), binary()} | {:error, :not_null_terminated}
  def decode_string(bin) do
    case :binary.match(bin, <<0>>) do
      :nomatch ->
        {:error, :not_null_terminated}

      {pos, 1} ->
        {string, <<0, rest::binary>>} = :erlang.split_binary(bin, pos)
        {:ok, string, rest}
    end
  end

  @spec md5_request(<<_::32>>) :: iodata()
  def md5_request(salt), do: [<<?R, 12::32, 5::32>>, salt]

  @spec exchange_first_message(binary, binary | boolean, pos_integer) :: binary
  def exchange_first_message(nonce, salt \\ false, iterations \\ 4096) do
    server_nonce =
      16
      |> :pgo_scram.get_nonce()
      |> Base.encode64()

    secret = if salt, do: salt, else: server_nonce
    "r=#{nonce <> server_nonce},s=#{secret},i=#{iterations}"
  end

  @spec exchange_message(:first | :final, binary()) :: iodata()
  def exchange_message(type, message) do
    code =
      case type do
        :first -> 11
        :final -> 12
      end

    [<<?R, byte_size(message) + 8::32, code::32>>, message]
  end

  @spec error_message(binary(), binary()) :: iodata()
  def error_message(code, value) do
    message = ["SFATAL", 0, "VFATAL", 0, "C", code, 0, "M", value, 0, 0]
    [<<?E, IO.iodata_length(message) + 4::32>>, message]
  end

  @spec encode_error_message(list()) :: iodata()
  def encode_error_message(message) when is_list(message) do
    message = Enum.join(message, <<0>>) <> <<0, 0>>
    [<<?E, byte_size(message) + 4::32>>, message]
  end

  @spec encode_parameter_status(map) :: iodata()
  def encode_parameter_status(ps) do
    for {key, value} <- ps do
      encode_pkt(:parameter_status, key, value)
    end
  end

  @spec encode_pkt(:parameter_status, binary, binary) :: iodata()
  def encode_pkt(:parameter_status, key, value) do
    payload = [key, <<0>>, value, <<0>>]
    len = IO.iodata_length(payload) + 4
    [<<?S, len::integer-32>>, payload]
  end

  @spec backend_key_data() :: {iodata(), binary}
  def backend_key_data do
    pid = System.unique_integer([:positive, :monotonic])
    key = :crypto.strong_rand_bytes(4)
    payload = <<pid::integer-32, key::binary>>
    len = IO.iodata_length(payload) + 4
    {<<?K, len::32>>, payload}
  end

  @spec decode_startup_packet(binary()) :: {:ok, map()} | {:error, :bad_startup_payload}
  def decode_startup_packet(<<len::integer-32, _protocol::binary-4, rest::binary>>) do
    with {:ok, payload} <- decode_startup_packet_payload(rest) do
      pkt = %{
        len: len,
        payload: payload,
        tag: :startup
      }

      {:ok, pkt}
    end
  end

  def decode_startup_packet(_), do: {:error, :bad_startup_payload}

  @spec has_read_only_error?(list()) :: boolean
  def has_read_only_error?(pkts) do
    Enum.any?(pkts, fn
      %{payload: ["SERROR", "VERROR", "C25006" | _]} -> true
      _ -> false
    end)
  end

  @spec application_name :: binary()
  def application_name, do: @application_name

  @spec terminate_message :: binary()
  def terminate_message, do: @terminate_message

  @spec scram_request :: iodata()
  def scram_request, do: @scram_request

  @spec flush :: binary()
  def flush, do: @flush

  @spec sync :: binary()
  def sync, do: @sync

  @spec authentication_ok :: binary()
  def authentication_ok, do: @authentication_ok

  @spec ready_for_query :: binary()
  def ready_for_query, do: @ready_for_query

  @spec ssl_request :: binary()
  def ssl_request, do: @ssl_request

  # Internal functions

  @spec decode(binary(), list()) :: [Pkt.t()]
  defp decode(data, acc) when byte_size(data) >= @pkt_header_size do
    {:ok, pkt, rest} = decode_pkt(data)
    decode(rest, [pkt | acc])
  end

  defp decode(_, acc), do: Enum.reverse(acc)

  @spec tag(char()) :: atom()
  defp tag(char) do
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
      ?p -> :password_message
      _ -> :undefined
    end
  end

  @spec decode_payload(:authentication, binary()) ::
          atom() | {atom(), binary()} | {:undefined, any()}
  defp decode_payload(:authentication, payload) do
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

  @spec decode_payload(:parameter_status, binary()) :: {binary(), binary()} | :undefined
  defp decode_payload(:parameter_status, payload) do
    case String.split(payload, <<0>>, trim: true) do
      [k, v] -> {k, v}
      _ -> :undefined
    end
  end

  @spec decode_payload(:backend_key_data, binary()) :: %{pid: pos_integer(), key: binary()}
  defp decode_payload(:backend_key_data, <<pid::integer-32, key::integer-32>>),
    do: %{pid: pid, key: key}

  @spec decode_payload(:ready_for_query, binary()) :: :idle | :transaction | :error
  defp decode_payload(:ready_for_query, payload) do
    case payload do
      "I" -> :idle
      "T" -> :transaction
      "E" -> :error
    end
  end

  @spec decode_payload(:parse_complete, binary()) :: :parse_complete
  defp decode_payload(:parse_complete, ""), do: :parse_complete

  @spec decode_payload(:parameter_description, binary()) :: {pos_integer(), list()}
  defp decode_payload(:parameter_description, <<count::integer-16, rest::binary>>),
    do: {count, decode_parameter_description(rest, [])}

  @spec decode_payload(:row_description, binary()) :: list()
  defp decode_payload(:row_description, <<count::integer-16, rest::binary>>),
    do: decode_row_description(count, rest, [])

  @spec decode_payload(:data_row, binary()) :: nil
  defp decode_payload(:data_row, _payload), do: nil

  # https://www.postgresql.org/docs/current/protocol-error-fields.html
  @spec decode_payload(:error_response, binary()) :: [binary()]
  defp decode_payload(:error_response, payload),
    do: String.split(payload, <<0>>, trim: true)

  @spec decode_payload(:password_message, binary()) ::
          {:scram_sha_256, map()} | {:md5, binary()} | :undefined
  defp decode_payload(
         :password_message,
         <<"SCRAM-SHA-256", 0, _::32, channel::binary-3, bin::binary>>
       ) do
    case kv_to_map(bin) do
      {:ok, map} ->
        channel =
          case channel do
            "n,," -> "biws"
            "y,," -> "eSws"
          end

        {:scram_sha_256, Map.put(map, "c", channel)}

      {:error, _} ->
        :undefined
    end
  end

  defp decode_payload(:password_message, "md5" <> _ = bin) do
    case :binary.split(bin, <<0>>) do
      [digest, ""] -> {:md5, digest}
      _ -> :undefined
    end
  end

  @spec decode_payload(:password_message, binary()) ::
          {:first_msg_response, map()} | :undefined
  defp decode_payload(:password_message, bin) do
    case kv_to_map(bin) do
      {:ok, map} -> {:first_msg_response, map}
      {:error, _} -> :undefined
    end
  end

  defp decode_payload(_, _), do: :undefined

  @spec kv_to_map(binary()) :: {:ok, map()} | {:error, String.t()}
  defp kv_to_map(bin) do
    Regex.scan(~r/(\w+)=([^,]*)/, bin)
    |> Map.new(fn [_, k, v] -> {k, v} end)
    |> case do
      map when map_size(map) > 0 -> {:ok, map}
      _ -> {:error, "invalid key value string"}
    end
  end

  @spec decode_row_description(non_neg_integer(), binary(), list()) :: [map()] | {:error, :decode}
  defp decode_row_description(0, "", acc), do: Enum.reverse(acc)

  defp decode_row_description(count, rest, acc) do
    with {:ok, field_name,
          <<table_oid::integer-32, attr_num::integer-16, data_type_oid::integer-32,
            data_type_size::integer-16, type_modifier::integer-32, format_code::integer-16,
            tail::binary>>} <- decode_string(rest),
         {:ok, format} <- decode_format_code(format_code) do
      field = %{
        name: field_name,
        type_info: PgType.type(data_type_oid),
        table_oid: table_oid,
        attr_number: attr_num,
        data_type_oid: data_type_oid,
        data_type_size: data_type_size,
        type_modifier: type_modifier,
        format: format
      }

      decode_row_description(count - 1, tail, [field | acc])
    else
      _ -> {:error, :decode}
    end
  end

  @spec decode_format_code(0 | 1) :: {:ok, :text | :binary} | {:error, :unknown_format_code}
  defp decode_format_code(code) do
    case code do
      0 -> {:ok, :text}
      1 -> {:ok, :binary}
      _ -> {:error, :unknown_format_code}
    end
  end

  @spec decode_parameter_description(binary(), list()) :: [pos_integer()]
  defp decode_parameter_description("", acc), do: Enum.reverse(acc)

  defp decode_parameter_description(<<oid::integer-32, rest::binary>>, acc),
    do: decode_parameter_description(rest, [oid | acc])

  # The startup packet payload is a list of key/value pairs, separated by null bytes
  @spec decode_startup_packet_payload(binary()) :: {:ok, map()} | {:error, :bad_startup_payload}
  defp decode_startup_packet_payload(payload) do
    fields = String.split(payload, <<0>>, trim: true)

    # If the number of fields is odd, then the payload is malformed
    if rem(length(fields), 2) == 1 do
      {:error, :bad_startup_payload}
    else
      map =
        fields
        |> Enum.chunk_every(2)
        |> Enum.map(fn
          ["options" = k, v] -> {k, URI.decode_query(v)}
          [k, v] -> {k, v}
        end)
        |> Map.new()

      # We only do light validation on the fields in the payload. The only field we use at the
      # moment is `user`. If that's missing, this is a bad payload.
      if Map.has_key?(map, "user"),
        do: {:ok, map},
        else: {:error, :bad_startup_payload}
    end
  end
end
