defmodule Supavisor.TLSHandshake.OverloadProtectionTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Supavisor.TLSHandshake.OverloadProtection

  test "drop?/2 drops starts that waited over twice the target once an interval's shortest wait is above the target" do
    ms = &System.convert_time_unit(&1, :millisecond, :native)
    drop? = fn at, waited -> OverloadProtection.drop?(ms.(at), ms.(waited)) end

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

  test "drop?/2 logs when an interval's shortest wait goes above the target and back" do
    ms = &System.convert_time_unit(&1, :millisecond, :native)
    drop? = fn at, waited -> OverloadProtection.drop?(ms.(at), ms.(waited)) end

    refute drop?.(0, 150)

    # No start is dropped, but the interval's shortest wait was above the target.
    log = capture_log(fn -> refute drop?.(1_000, 150) end)

    assert log =~
             "TLS handshake queue overloaded: shortest wait was 150ms, target is 100ms"

    # Staying overloaded doesn't log again.
    assert capture_log(fn -> refute drop?.(2_000, 150) end) == ""
    assert capture_log(fn -> refute drop?.(3_000, 10) end) == ""
    # That interval's shortest wait was 10ms, so the queue recovered.
    assert capture_log(fn -> refute drop?.(4_000, 150) end) =~
             "TLS handshake queue recovered: shortest wait was 10ms, target is 100ms"

    # Going above the target again logs again.
    assert capture_log(fn -> refute drop?.(5_000, 150) end) =~ "TLS handshake queue overloaded"
  end
end
