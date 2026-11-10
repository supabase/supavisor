defmodule Supavisor.TLSHandshakeTest do
  use ExUnit.Case, async: true

  alias Supavisor.TLSHandshake

  test "queue_drop?/2 drops starts that waited over twice the target once an interval's shortest wait is above the target" do
    ms = &System.convert_time_unit(&1, :millisecond, :native)
    drop? = fn at, waited -> TLSHandshake.queue_drop?(ms.(at), ms.(waited)) end

    # First interval: every start waited 250ms, none is dropped.
    refute drop?.(0, 250)
    refute drop?.(10, 250)
    # The next interval starts slow. Its first start is never dropped.
    refute drop?.(1_000, 250)
    assert drop?.(1_010, 250)
    refute drop?.(1_020, 150)
    # That interval's shortest wait was 150ms, still above the target.
    refute drop?.(2_000, 10)
    assert drop?.(2_010, 250)
    # Its shortest wait was 10ms, so the queue recovered.
    refute drop?.(3_000, 250)
    refute drop?.(3_010, 250)
  end

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
