defmodule Supavisor.Protocol.Client do
  require Logger

  @pkt_header_size 5

  defmodule Pkt do
    defstruct([:tag, :len, :payload, :bin])

    @type t :: %Pkt{
            tag: atom,
            len: integer,
            payload: any,
            bin: binary
          }
  end

  def pkt_header_size, do: @pkt_header_size

  def header(<<char::8, pkt_len::32>>) do
    {tag(char), pkt_len}
  end

  @spec decode(binary) :: {:ok, [Pkt.t()], binary} | {:error, any}
  def decode(data) do
    decode(data, [])
  end

  @spec decode(binary, [Pkt.t()]) :: {:ok, [Pkt.t()], binary} | {:error, any}
  def decode("", acc), do: {:ok, Enum.reverse(acc), ""}

  def decode(data, acc) do
    case decode_pkt(data) do
      {:ok, pkt, rest} -> decode(rest, [pkt | acc])
      {:error, :payload_too_small} -> {:ok, Enum.reverse(acc), data}
    end
  end

  @spec decode_pkt(binary) ::
          {:ok, Pkt.t(), binary}
          | {:acc, nil, binary}
          | {:error, :payload_too_small}
  def decode_pkt(<<_::8, pkt_len::32, payload::binary>>)
      when byte_size(payload) < pkt_len - 4 do
    {:error, :payload_too_small}
  end

  def decode_pkt(<<char::8, pkt_len::32, rest::binary>>) do
    case tag(char) do
      nil ->
        {:error, {:undefined_tag, <<char>>}}

      tag ->
        payload_len = pkt_len - 4
        <<bin_payload::binary-size(payload_len), rest2::binary>> = rest

        {:ok,
         %Pkt{
           tag: tag,
           len: pkt_len + 1,
           payload: decode_payload(tag, bin_payload),
           bin: <<char, pkt_len::32, bin_payload::binary>>
         }, rest2}
    end
  end

  def decode_pkt(_), do: {:error, :header_mismatch}

  @spec get_payload(binary | any()) :: {:ok, String.t()} | {:error, any}
  def get_payload(<<char::8, pkt_len::32, rest::binary>>) do
    case tag(char) do
      nil ->
        {:error, {:undefined_tag, <<char>>}}

      tag ->
        try do
          payload_len = pkt_len - 4
          <<bin_payload::binary-size(payload_len), _::binary>> = rest

          {:ok, decode_payload(tag, bin_payload)}
        rescue
          reason ->
            {:error, {:decode_payload_error, reason}}
        end
    end
  end

  def get_payload(msg), do: {:error, {:invalid_msg, msg}}

  @spec tag(byte) :: atom | nil
  def tag(char) do
    case char do
      ?Q -> :simple_query
      ?H -> :flush_message
      ?P -> :parse_message
      ?B -> :bind_message
      ?D -> :describe_message
      ?E -> :execute_message
      ?S -> :sync_message
      ?X -> :termination_message
      ?C -> :close_message
      _ -> nil
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
      [""] ->
        :undefined

      other ->
        case Enum.filter(other, &(&1 != "")) do
          [sql] -> sql
          message -> message
        end
    end
  end

  def decode_payload(:describe_message, <<char::binary-size(1), str_name::binary>>) do
    str_name = String.trim_trailing(str_name, <<0>>)
    %{char: char, str_name: str_name}
  end

  def decode_payload(:close_message, <<char::binary-size(1), str_name::binary>>) do
    str_name = String.trim_trailing(str_name, <<0>>)
    %{char: char, str_name: str_name}
  end

  def decode_payload(:flush_message, <<4::32>>), do: nil

  def decode_payload(:termination_message, _payload), do: nil

  def decode_payload(:bind_message, _payload), do: nil

  def decode_payload(:execute_message, _payload), do: nil

  def decode_payload(_tag, ""), do: nil

  def decode_payload(_tag, payload) do
    Logger.error("undefined payload: #{inspect(payload)}")
    :undefined
  end

  def decode_startup_packet(<<len::32, _protocol::binary-4, rest::binary>>) do
    # <<major::16, minor::16>> = protocol

    %Pkt{
      len: len,
      payload:
        String.split(rest, <<0>>, trim: true)
        |> Enum.chunk_every(2)
        |> Enum.into(%{}, fn [k, v] -> {k, v} end),
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
