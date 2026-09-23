defmodule Supavisor.ConnectionListenerTest do
  use ExUnit.Case, async: true

  alias Supavisor.ConnectionListener

  setup ctx do
    listener = start_supervised!({ConnectionListener, [name: ctx.test]})
    ref = make_ref()

    :telemetry.attach(
      {ctx.test, :stop},
      [:supavisor, :auth_query, :connection, :stop],
      fn _, meas, meta, {pid, r} -> send(pid, {r, :stop, meas, meta}) end,
      {self(), ref}
    )

    :telemetry.attach(
      {ctx.test, :exception},
      [:supavisor, :auth_query, :connection, :exception],
      fn _, meas, meta, {pid, r} -> send(pid, {r, :exception, meas, meta}) end,
      {self(), ref}
    )

    :telemetry.attach(
      {ctx.test, :disconnection},
      [:supavisor, :auth_query, :disconnection],
      fn _, meas, meta, {pid, r} -> send(pid, {r, :disconnection, meas, meta}) end,
      {self(), ref}
    )

    on_exit(fn ->
      :telemetry.detach({ctx.test, :stop})
      :telemetry.detach({ctx.test, :exception})
    end)

    {:ok, listener: listener, ref: ref}
  end

  defp fake_conn,
    do:
      spawn(fn ->
        receive do
          :stop_normal -> exit(:normal)
        end
      end)

  defp sync(listener), do: :sys.get_state(listener)

  describe ":connected" do
    test "emits connection:stop with non-negative duration", %{listener: l, ref: ref} do
      pid = fake_conn()
      send(l, {:connected, pid, System.monotonic_time()})
      assert_receive {^ref, :stop, %{duration: d}, _}
      assert is_integer(d) and d >= 0
    end

    test "uses stored disconnect_time as start for reconnection", %{listener: l, ref: ref} do
      pid = fake_conn()
      tag = System.monotonic_time()

      Process.sleep(100)
      send(l, {:connected, pid, tag})
      assert_receive {^ref, :stop, %{duration: _duration1}, _}

      send(l, {:disconnected, pid, nil})
      # Pass the original tag as the actual Postgrex would
      # — the listener should use disconnect_time instead
      send(l, {:connected, pid, tag})
      assert_receive {^ref, :stop, %{duration: duration2}, _}
      # if the original start_time was used, duration2 would be at least 100ms
      assert is_integer(duration2) and
               duration2 < System.convert_time_unit(100, :millisecond, :native)
    end
  end

  describe ":disconnection" do
    test "emitted on normal disconnect", %{listener: l, ref: ref} do
      pid = fake_conn()
      send(l, {:connected, pid, System.monotonic_time()})
      assert_receive {^ref, :stop, _, _}

      send(l, {:disconnected, pid, nil})
      assert_receive {^ref, :disconnection, %{count: 1}, _}
    end

    test "handles duplicate :disconnected gracefully", %{listener: l, ref: ref} do
      pid = fake_conn()
      send(l, {:connected, pid, System.monotonic_time()})

      send(l, {:disconnected, pid, nil})
      send(l, {:disconnected, pid, nil})
      assert_receive {^ref, :disconnection, _, _}
      refute_receive {^ref, :disconnection, _, _}
      assert Process.alive?(l)
    end
  end

  describe ":DOWN" do
    test "normal exit — emitted if has previously connected", %{listener: l, ref: ref} do
      pid = fake_conn()
      send(l, {:connected, pid, System.monotonic_time()})
      assert_receive {^ref, :stop, _, _}

      send(pid, :stop_normal)
      assert_receive {^ref, :disconnection, _, _}
    end

    test "normal exit — no event emitted if has previously disconnected", %{
      listener: l,
      ref: ref
    } do
      pid = fake_conn()
      send(l, {:connected, pid, System.monotonic_time()})
      assert_receive {^ref, :stop, _, _}

      send(l, {:disconnected, pid, nil})
      assert_receive {^ref, :disconnection, _, _}

      send(pid, :stop_normal)
      refute_receive {^ref, :disconnection, _, _}
    end

    test "non-normal exit — emits disconnection if if has previously connected", %{
      listener: l,
      ref: ref
    } do
      pid = fake_conn()
      send(l, {:connected, pid, System.monotonic_time()})
      assert_receive {^ref, :stop, _, _}

      Process.exit(pid, :some_error)
      assert_receive {^ref, :disconnection, _, %{kind: :exit, reason: :some_error}}
    end

    test "non-normal exit — do not emits disocnnection if if has previously disconnected", %{
      listener: l,
      ref: ref
    } do
      pid = fake_conn()
      send(l, {:connected, pid, System.monotonic_time()})
      assert_receive {^ref, :stop, _, _}

      send(l, {:disconnected, pid, nil})
      assert_receive {^ref, :disconnection, _, _}

      Process.exit(pid, :some_error)
      refute_receive {^ref, :disconnection, _, _}
    end

    test "no crash when :DOWN arrives for unknown pid", %{listener: l} do
      unknown = spawn(fn -> :ok end)
      Process.sleep(10)
      send(l, {:DOWN, make_ref(), :process, unknown, :reason})
      sync(l)
      assert Process.alive?(l)
    end
  end
end
