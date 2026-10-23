defmodule Supavisor.PromEx.Plugins.Tenant.ConnectionRequestBucketsTest do
  use ExUnit.Case, async: true

  alias Supavisor.PromEx.Plugins.Tenant.ConnectionRequestBuckets, as: Buckets

  # SLO latency thresholds must equal a bucket boundary exactly, so these must stay boundaries
  @slo_thresholds_ms [100, 250, 500, 1_000, 2_500]

  test "has a boundary at every threshold the SLOs use" do
    for threshold <- @slo_thresholds_ms do
      bucket = Buckets.bucket_for(threshold - 0.001, %{})

      assert bucket |> Buckets.upper_bound(%{}) |> String.to_float() == threshold * 1.0,
             "no bucket boundary at #{threshold}ms"
    end
  end

  test "covers pool checkout waits up to the 60s default and beyond" do
    upper = fn value -> value |> Buckets.bucket_for(%{}) |> Buckets.upper_bound(%{}) end

    assert Buckets.number_of_buckets(%{}) == 21
    assert String.to_float(upper.(59_999.0)) == 60_000.0
    assert String.to_float(upper.(60_001.0)) == 120_000.0
    assert upper.(121_000.0) == "+Inf"
  end
end
