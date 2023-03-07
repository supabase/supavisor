defmodule Supavisor.Helpers do
  @moduledoc """
  This module includes helper functions for different contexts that can't be union in one module.
  """

  @spec encrypt!(<<_::128>>, binary()) :: binary()
  def encrypt!(secret_key, text) do
    :aes_128_ecb
    |> :crypto.crypto_one_time(secret_key, pad(text), true)
    |> Base.encode64()
  end

  @spec decrypt!(<<_::128>>, binary()) :: binary()
  def decrypt!(secret_key, base64_text) do
    crypto_text = Base.decode64!(base64_text)

    :aes_128_ecb
    |> :crypto.crypto_one_time(secret_key, crypto_text, false)
    |> unpad()
  end

  defp pad(data) do
    to_add = 16 - rem(byte_size(data), 16)
    data <> :binary.copy(<<to_add>>, to_add)
  end

  defp unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end
end
