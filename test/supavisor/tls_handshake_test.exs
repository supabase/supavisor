defmodule Supavisor.TLSHandshakeTest do
  use ExUnit.Case, async: true

  alias Supavisor.TLSHandshake

  test "overloaded_alert/0 is read by a TLS client as a fatal internal_error alert" do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false])
    {:ok, port} = :inet.port(listen)

    server =
      Task.async(fn ->
        {:ok, sock} = :gen_tcp.accept(listen)
        :ok = :gen_tcp.send(sock, TLSHandshake.overloaded_alert())
        :gen_tcp.close(sock)
      end)

    assert {:error, {:tls_alert, {:internal_error, _}}} =
             :ssl.connect(~c"localhost", port, [verify: :verify_none], 5_000)

    Task.await(server)
  end
end
