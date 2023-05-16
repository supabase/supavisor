defmodule Supavisor.Protocol.Client do
  @moduledoc """
  This module is responsible for decoding data sent to the PostgreSQL server. It provides several functions to decode payloads from different types of messages.

  Message Formats: https://www.postgresql.org/docs/current/protocol-message-formats.html
  Error codes https://www.postgresql.org/docs/current/errcodes-appendix.html
  """
  require Logger

  alias Supavisor.CDC.Error

  @pkt_header_size 5

  defmodule Pkt do
    @moduledoc "Representing a packet structure with tag, length, and payload fields."
    defstruct([:tag, :len, :payload])
  end

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

  defp decode_pkt(<<char::integer-8, pkt_len::integer-32, rest::binary>>) do
    tag = tag(char)
    payload_len = pkt_len - 4

    <<bin_payload::binary-size(payload_len), rest2::binary>> = rest

    payload = decode_payload(tag, bin_payload)

    {:ok, %Pkt{tag: tag, len: pkt_len + 1, payload: payload}, rest2}
  end

  defp tag(char) do
    case char do
      ?Q -> :query
      _ -> :undefined
    end
  end

  defp decode_payload(:query, bin) do
    String.trim_trailing(bin, <<0>>)
  end

  def encode(:query, payload) do
    payload = payload <> <<0>>
    len = byte_size(payload) + 4
    <<?Q, len::integer-32, payload::binary>>
  end

  def encode(%Error{} = error) do
    fields = [
      error_field("S", "ERROR"),
      error_field("C", error.code),
      error_field("M", error.message),
      error_field("H", error.hint),
      <<0>>
    ]

    payload = Enum.join(fields, "")

    len = byte_size(payload) + 4
    <<?E, len::integer-32, payload::binary>>
  end

  defp error_field(_, nil), do: ""

  defp error_field("C", :data_exception) do
    <<"C"::binary, "22000"::binary, 0::integer-8>>
  end

  defp error_field(type, value) do
    <<type::binary, value::binary, 0::integer-8>>
  end

  def encode_ready_for_query do
    backend_state = <<?I>>
    payload = backend_state
    len = byte_size(payload) + 4
    <<?Z, len::integer-32, payload::binary>>
  end
end
