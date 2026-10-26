defmodule SupavisorWeb.PoolPid do
  @moduledoc """
  Opaque API handle of a pool supervisor's pid

  An Erlang/Elixir pid carries the node and the node's incarnation, so it identifies
  this exact supervisor anywhere in the cluster.
  """

  @spec encode(pid()) :: String.t()
  def encode(pid) when is_pid(pid),
    do: pid |> :erlang.term_to_binary() |> Base.url_encode64(padding: false)

  @doc """
  Reverses `encode/1`. `:safe` rejects terms that would create atoms, e.g. a pid
  of a node this one has never seen.
  """
  # Anything but a pid is rejected, so a decoded fun is never called.
  # sobelow_skip ["Misc.BinToTerm"]
  @spec decode(String.t()) :: {:ok, pid()} | :error
  def decode(encoded) do
    with {:ok, binary} <- Base.url_decode64(encoded, padding: false),
         pid when is_pid(pid) <- :erlang.binary_to_term(binary, [:safe]) do
      {:ok, pid}
    else
      _ -> :error
    end
  rescue
    ArgumentError -> :error
  end
end
