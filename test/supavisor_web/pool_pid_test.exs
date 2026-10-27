defmodule SupavisorWeb.PoolPidTest do
  use ExUnit.Case, async: true

  alias SupavisorWeb.PoolPid

  test "decode/1 reverses encode/1" do
    assert self() |> PoolPid.encode() |> PoolPid.decode() == {:ok, self()}
  end

  test "decode/1 rejects input that is not Base64 of a term" do
    assert PoolPid.decode("garbage") == :error
    assert PoolPid.decode(Base.url_encode64("garbage", padding: false)) == :error
  end

  test "decode/1 rejects a term that is not a pid" do
    not_a_pid = :ok |> :erlang.term_to_binary() |> Base.url_encode64(padding: false)
    assert PoolPid.decode(not_a_pid) == :error
  end

  test "decode/1 rejects a pid of a node whose name is not an existing atom" do
    node = Atom.to_string(node())
    # Same length as the real name, so only the name changes in the encoded pid.
    unknown =
      byte_size(node)
      |> :crypto.strong_rand_bytes()
      |> Base.encode32(case: :lower)
      |> binary_part(0, byte_size(node))

    encoded =
      self()
      |> :erlang.term_to_binary()
      |> :binary.replace(node, unknown)
      |> Base.url_encode64(padding: false)

    assert PoolPid.decode(encoded) == :error
    assert_raise ArgumentError, fn -> String.to_existing_atom(unknown) end
  end
end
