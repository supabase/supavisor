defmodule Supavisor.ClientHandler.ErrorTest do
  use ExUnit.Case, async: true

  require Supavisor

  alias Supavisor.ClientHandler.Error
  alias Supavisor.Errors.MaxConnectionsError

  describe "terminate_with_error/3 with MaxConnectionsError" do
    test "delays the response by ~500ms before sending it" do
      {_client, server} = sockpair()
      data = %{sock: {:gen_tcp, server}, id: unique_id()}
      exception = MaxConnectionsError.new(:transaction, 100)

      started_at = System.monotonic_time(:millisecond)
      assert {:stop, :normal} = Error.terminate_with_error(data, exception, :handshake)
      elapsed = System.monotonic_time(:millisecond) - started_at

      assert elapsed >= 500
    end
  end

  defp unique_id,
    do:
      Supavisor.id(
        type: :single,
        tenant: "test_#{System.unique_integer([:positive])}",
        user: "user",
        mode: :transaction,
        db: "db"
      )

  defp sockpair do
    {:ok, listen} = :gen_tcp.listen(0, mode: :binary, active: false)
    {:ok, {address, port}} = :inet.sockname(listen)
    this = self()
    ref = make_ref()

    spawn(fn ->
      {:ok, server} = :gen_tcp.accept(listen)
      :gen_tcp.controlling_process(server, this)
      send(this, {ref, server})
    end)

    {:ok, client} = :gen_tcp.connect(address, port, mode: :binary, active: false)
    assert_receive {^ref, server}

    {client, server}
  end
end
