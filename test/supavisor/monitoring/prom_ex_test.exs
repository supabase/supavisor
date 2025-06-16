defmodule Supavisor.Monitoring.PromExTest do
  use Supavisor.DataCase, async: true
  use ExUnitProperties

  @subject Supavisor.Monitoring.PromEx

  describe "get_metrics/1" do
    @sources %{
      {:darwin, :aarch64} => {
        "https://github.com/prometheus/prom2json/releases/download/v1.4.1/prom2json-1.4.1.darwin-arm64.tar.gz",
        "prom2json-1.4.1.darwin-arm64/prom2json"
      },
      {:linux, :aarch64} => {
        "https://github.com/prometheus/prom2json/releases/download/v1.4.1/prom2json-1.4.1.linux-arm64.tar.gz",
        "prom2json-1.4.1.linux-arm64/prom2json"
      }
    }

    setup do
      {:ok, prom2json: Supavisor.Downloader.ensure("prom2json", @sources)}
    end

    @tag :tmp_dir
    test "returned metrics are parseable", %{tmp_dir: dir, prom2json: exe} do
      metrics = @subject.get_metrics()
      file = Path.join(dir, "prom.out")
      File.write!(file, metrics)

      assert {_, 0} = System.cmd(exe, [file])
    end

    @tag :tmp_dir
    property "non-standard DB names do not cause parsing issues", %{tmp_dir: dir, prom2json: exe} do
      tenant = "tenant"
      user = "user"

      check all db_name <- string(:printable, min_length: 1, max_length: 63) do
        Supavisor.Monitoring.Telem.client_join(
          :ok,
          {{:single, tenant}, user, :session, db_name, nil}
        )

        metrics = @subject.get_metrics()
        file = Path.join(dir, "prom.out")
        File.write!(file, metrics)

        assert {out, 0} = System.cmd(exe, [file])
        assert {:ok, measurements} = JSON.decode(out)

        assert %{"metrics" => metrics} =
                 Enum.find(measurements, &(&1["name"] == "supavisor_client_joins_ok"))

        assert Enum.find(metrics, &(&1["labels"]["db_name"] == db_name))
      end
    end

    @tag :tmp_dir
    property "non-standard user names do not cause parsing issues", %{
      tmp_dir: dir,
      prom2json: exe
    } do
      tenant = "tenant"
      db_name = "db_name"

      check all user <- string(:printable, min_length: 1, max_length: 63) do
        Supavisor.Monitoring.Telem.client_join(
          :ok,
          {{:single, tenant}, user, :session, db_name, nil}
        )

        metrics = @subject.get_metrics()
        file = Path.join(dir, "prom.out")
        File.write!(file, metrics)

        assert {out, 0} = System.cmd(exe, [file])
        assert {:ok, measurements} = JSON.decode(out)

        assert %{"metrics" => metrics} =
                 Enum.find(measurements, &(&1["name"] == "supavisor_client_joins_ok"))

        assert Enum.find(metrics, &(&1["labels"]["db_name"] == db_name))
      end
    end

    @tag :tmp_dir
    property "non-standard tenant names do not cause parsing issues", %{
      tmp_dir: dir,
      prom2json: exe
    } do
      db_name = "db_name"
      user = "user"

      check all tenant <- string(:printable, min_length: 1) do
        Supavisor.Monitoring.Telem.client_join(
          :ok,
          {{:single, tenant}, user, :session, db_name, nil}
        )

        metrics = @subject.get_metrics()
        file = Path.join(dir, "prom.out")
        File.write!(file, metrics)

        assert {out, 0} = System.cmd(exe, [file])
        assert {:ok, measurements} = JSON.decode(out)

        assert %{"metrics" => metrics} =
                 Enum.find(measurements, &(&1["name"] == "supavisor_client_joins_ok"))

        assert Enum.find(metrics, &(&1["labels"]["db_name"] == db_name))
      end
    end
  end
end
