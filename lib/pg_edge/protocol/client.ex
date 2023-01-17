defmodule PgEdge.Protocol.Client do
  require Logger

  @pkt_header_size 5

  defmodule(Pkt,
    do: defstruct([:tag, :len, :payload, :bin])
  )

  def stream(bin) do
    Stream.resource(
      fn -> {:bin, bin} end,
      fn
        <<>> ->
          {:halt, nil}

        {:bin, data} ->
          if byte_size(data) >= @pkt_header_size do
            case decode_pkt(data) do
              {:ok, pkt, rest} ->
                {[pkt], {:bin, rest}}

              {:acc, nil, rest} ->
                {[{:rest, rest}], <<>>}
            end
          else
            {[{:rest, data}], <<>>}
          end
      end,
      fn _ -> :ok end
    )
  end

  def header(<<char::integer-8, pkt_len::integer-32>>) do
    {tag(char), pkt_len}
  end

  def decode(data) do
    decode(data, [])
  end

  def decode(data, acc) when byte_size(data) >= @pkt_header_size do
    case decode_pkt(data) do
      {:ok, pkt, rest} -> decode(rest, [pkt | acc])
      {:acc, nil, bin} -> {:ok, Enum.reverse(acc), bin}
    end
  end

  def decode(_, acc) do
    {:ok, Enum.reverse(acc), ""}
  end

  def decode_pkt(
        <<char::integer-8, pkt_len::integer-32, rest::binary>> = bin,
        decode_payload \\ true
      ) do
    tag = tag(char)
    payload_len = pkt_len - 4

    if byte_size(rest) >= payload_len do
      <<bin_payload::binary-size(payload_len), rest2::binary>> = rest

      payload =
        if decode_payload do
          decode_payload(tag, bin_payload)
        else
          nil
        end

      {:ok,
       %Pkt{
         tag: tag,
         len: pkt_len + 1,
         payload: payload,
         bin: <<char, pkt_len::integer-32, bin_payload::binary>>
       }, rest2}
    else
      {:acc, nil, bin}
    end
  end

  def tag(char) do
    case char do
      ?Q ->
        :simple_query

      ?H ->
        :flush_message

      ?P ->
        :parse_message

      ?B ->
        :bind_message

      ?D ->
        :describe_message

      ?E ->
        :execute_message

      ?S ->
        :sync_message

      ?X ->
        :termination_message

      _ ->
        Logger.error("undefined tag char: #{inspect(<<char>>)}")
        :undefined
    end
  end

  def decode_payload(:simple_query, payload) do
    case String.split(payload, <<0>>) do
      [query, ""] -> query
      _ -> :undefined
    end
  end

  def decode_payload(:parse_message, payload) do
    case String.split(payload, <<0>>) do
      [""] -> :undefined
      other -> other
    end
  end

  def decode_payload(:describe_message, <<char::binary-size(1), str_name::binary>>) do
    %{char: char, str_name: str_name}
  end

  def decode_payload(:flush_message, <<4::integer-32>>) do
    nil
  end

  def decode_payload(:termination_message, _payload) do
    nil
  end

  def decode_payload(:bind_message, _payload) do
    nil
  end

  def decode_payload(:execute_message, _payload) do
    nil
  end

  def decode_payload(_tag, "") do
    nil
  end

  def decode_payload(_tag, payload) do
    Logger.error("undefined payload: #{inspect(payload)}")
    :undefined
  end

  def decode_startup_packet(<<len::integer-32, _protocol::binary-4, rest::binary>>) do
    # <<major::integer-16, minor::integer-16>> = protocol

    %Pkt{
      len: len,
      payload: String.split(rest, <<0>>, trim: true) |> Enum.chunk_every(2),
      tag: :startup
    }
  end

  def decode_startup_packet(_) do
    :undef
  end

  def parse_msg_sel_1() do
    <<80, 0, 0, 0, 16, 0, 115, 101, 108, 101, 99, 116, 32, 49, 0, 0, 0, 66, 0, 0, 0, 12, 0, 0, 0,
      0, 0, 0, 0, 0, 68, 0, 0, 0, 6, 80, 0, 69, 0, 0, 0, 9, 0, 0, 0, 0, 200, 83, 0, 0, 0, 4>>
  end
end
