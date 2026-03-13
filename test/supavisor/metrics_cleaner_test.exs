defmodule Supavisor.MetricsCleanerTest do
  use ExUnit.Case, async: false

  alias Supavisor.PromEx.Plugins.Tenant, as: Metrics

  @subject Supavisor.MetricsCleaner

  doctest @subject

  setup ctx do
    :telemetry.attach(ctx, [:supavisor, :metrics_cleaner, :stop], &__MODULE__.handler/4, %{
      parent: self()
    })

    :ok
  end

  def handler(_, measurements, _, %{parent: pid}) do
    send(pid, {:metrics, measurements})
  end

  test "metrics for unknown tenant are removed" do
    :ok =
      Metrics.emit_telemetry_for_tenant(
        {{{:single, "non-existent"}, "foo", :transaction, "bar", nil}, 2137}
      )

    metrics = Supavisor.Monitoring.PromEx.get_metrics()

    assert IO.iodata_to_binary(metrics) =~ ~r/non-existent/

    # First clean marks orphans (removes from tags_tid), second clean sweeps them
    @subject.clean()
    assert_receive {:metrics, _}
    @subject.clean()
    assert_receive {:metrics, _}

    metrics = Supavisor.Monitoring.PromEx.get_metrics()

    refute IO.iodata_to_binary(metrics) =~ ~r/non-existent/
  end

  test "sums/counters for unknown tenant are removed" do
    :ok =
      Supavisor.Monitoring.Telem.handler_action(
        :db_handler,
        :stopped,
        {{:single, "non-existent"}, "foo", :transaction, "bar", nil}
      )

    metrics = Supavisor.Monitoring.PromEx.get_metrics()

    assert IO.iodata_to_binary(metrics) =~ ~r/non-existent/

    @subject.clean()
    assert_receive {:metrics, _}
    @subject.clean()
    assert_receive {:metrics, _}

    metrics = Supavisor.Monitoring.PromEx.get_metrics()

    refute IO.iodata_to_binary(metrics) =~ ~r/non-existent/
  end

  test "tag tables are cleaned up for orphaned tenants" do
    {_, {tags_tid, _metric_tids, reverse_tags_tid, cache_tid}} =
      Peep.Persistent.storage(Supavisor.Monitoring.PromEx.Metrics)

    :ok =
      Metrics.emit_telemetry_for_tenant(
        {{{:single, "orphan-tags-test"}, "foo", :transaction, "bar", nil}, 42}
      )

    # Trigger a scrape so the cache_tid gets populated via the export path
    metrics = Supavisor.Monitoring.PromEx.get_metrics()
    assert IO.iodata_to_binary(metrics) =~ "orphan-tags-test"

    # The tags map stored in ETS matches the telemetry metadata filtered to @tags
    tags_map = %{
      tenant: "orphan-tags-test",
      user: "foo",
      mode: :transaction,
      type: :single,
      db_name: "bar",
      search_path: nil
    }

    [{^tags_map, tags_id}] = :ets.lookup(tags_tid, tags_map)

    # Verify entries exist in all three tag tables before cleanup
    assert :ets.lookup(tags_tid, tags_map) != []
    assert :ets.lookup(reverse_tags_tid, tags_id) != []
    assert :ets.lookup(cache_tid, tags_id) != []

    # First clean marks (deletes from tags_tid), second clean sweeps the rest
    @subject.clean()
    assert_receive {:metrics, _}

    # After mark: tags_tid is cleaned, but reverse_tags and cache remain
    assert :ets.lookup(tags_tid, tags_map) == []
    assert :ets.lookup(reverse_tags_tid, tags_id) != []
    assert :ets.lookup(cache_tid, tags_id) != []

    @subject.clean()
    assert_receive {:metrics, _}

    # After sweep: all three tag tables should be cleaned up
    assert :ets.lookup(tags_tid, tags_map) == []
    assert :ets.lookup(reverse_tags_tid, tags_id) == []
    assert :ets.lookup(cache_tid, tags_id) == []
  end
end
