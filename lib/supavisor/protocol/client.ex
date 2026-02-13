defmodule Supavisor.Protocol.Client do
  @moduledoc false

  require Logger

  @spec decode_startup_packet(binary()) :: {:ok, map()} | {:error, :bad_startup_payload}
  def decode_startup_packet(<<len::integer-32, _protocol::binary-4, rest::binary>>) do
    with {:ok, payload} <- decode_startup_packet_payload(rest) do
      {:ok, %{len: len, payload: payload, tag: :startup}}
    end
  end

  def decode_startup_packet(_), do: {:error, :bad_startup_payload}

  # The startup packet payload is a list of key/value pairs, separated by null bytes.
  # The payload is terminated by an extra null byte. Empty values are valid (e.g. options\x00\x00).
  @spec decode_startup_packet_payload(binary()) :: {:ok, map()} | {:error, :bad_startup_payload}
  defp decode_startup_packet_payload(payload) do
    fields = payload |> String.trim_trailing(<<0>>) |> String.split(<<0>>)

    # If the number of fields is odd, then the payload is malformed
    if rem(length(fields), 2) == 1 do
      {:error, :bad_startup_payload}
    else
      map =
        fields
        |> Enum.chunk_every(2)
        |> Enum.map(fn
          ["options" = k, v] -> {k, Supavisor.Protocol.StartupOptions.parse(v)}
          [k, v] -> {k, v}
        end)
        |> Map.new()

      # We only do light validation on the fields in the payload. The only field we use at the
      # moment is `user`. If that's missing, this is a bad payload.
      if Map.has_key?(map, "user") do
        {:ok, map}
      else
        Logger.error("Bad startup payload: #{inspect(payload, limit: 200)}")
        {:error, :bad_startup_payload}
      end
    end
  end
end
