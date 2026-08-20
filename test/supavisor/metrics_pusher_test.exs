defmodule Supavisor.MetricsPusherTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog

  require Supavisor

  alias Plug.Conn
  alias Supavisor.MetricsPusher
  alias Supavisor.Monitoring.Telem

  setup {Req.Test, :verify_on_exit!}

  # Helper function to start MetricsPusher and allow it to use Req.Test
  defp start_and_allow_pusher(opts) do
    opts = Keyword.put(opts, :interval, :timer.minutes(5))
    pid = start_supervised!({MetricsPusher, opts})
    Req.Test.allow(MetricsPusher, self(), pid)
    send(pid, :push)
    {:ok, pid}
  end

  describe "start_link/1" do
    test "does not start when URL is missing" do
      opts = [enabled: true]
      assert :ignore = MetricsPusher.start_link(opts)
    end

    test "sends request successfully" do
      opts = [
        url: "https://example.com:8428/api/v1/import/prometheus",
        user: "supavisor",
        auth: "hunter2",
        compress: true,
        timeout: 5000
      ]

      tenant = "metrics_pusher_test_tenant"

      Telem.client_join(
        :ok,
        Supavisor.id(type: :single, tenant: tenant, user: "u", mode: :session, db: "db")
      )

      parent = self()

      # A single request carrying this node's local metrics: both node-wide
      # (beam/OS-level) and tenant-tagged series live in the same collector.
      Req.Test.expect(MetricsPusher, 1, fn conn ->
        assert conn.method == "POST"
        assert conn.scheme == :https
        assert conn.host == "example.com"
        assert conn.port == 8428
        assert conn.request_path == "/api/v1/import/prometheus"

        assert Conn.get_req_header(conn, "authorization") == [
                 "Basic #{Base.encode64("supavisor:hunter2")}"
               ]

        assert Conn.get_req_header(conn, "content-type") == ["text/plain"]

        # Req.Test's plug adapter transparently decompresses gzip'd request
        # bodies (and strips content-encoding) before the plug sees them, so
        # the body here is already plaintext regardless of `compress: true`.
        {:ok, body, conn} = Conn.read_body(conn)

        send(parent, {:req_called, body})
        Req.Test.text(conn, "")
      end)

      {:ok, _pid} = start_and_allow_pusher(opts)

      assert_receive {:req_called, body}, 300

      assert body =~ "beam_stats_run_queue_count"
      assert body =~ "supavisor_client_joins_ok"
      assert body =~ ~s(tenant="#{tenant}")
    end

    test "sends request successfully without auth header" do
      opts = [
        url: "http://localhost:8428/api/v1/import/prometheus",
        compress: true,
        timeout: 5000
      ]

      parent = self()

      Req.Test.expect(MetricsPusher, 1, fn conn ->
        assert Conn.get_req_header(conn, "authorization") == []

        send(parent, :req_called)
        Req.Test.text(conn, "")
      end)

      {:ok, _pid} = start_and_allow_pusher(opts)
      assert_receive :req_called, 300
    end

    test "sends request body untouched when compress=false" do
      opts = [
        url: "http://localhost:8428/api/v1/import/prometheus",
        user: "hunter2",
        auth: "supavisor",
        compress: false,
        timeout: 5000
      ]

      parent = self()

      Req.Test.expect(MetricsPusher, 1, fn conn ->
        assert Conn.get_req_header(conn, "content-encoding") == []
        assert Conn.get_req_header(conn, "content-type") == ["text/plain"]

        send(parent, :req_called)
        Req.Test.text(conn, "")
      end)

      {:ok, _pid} = start_and_allow_pusher(opts)
      assert_receive :req_called, 300
    end

    test "when request receives non 2XX response" do
      opts = [
        url: "https://example.com:8428/api/v1/import/prometheus",
        auth: "hunter2",
        compress: true,
        timeout: 5000
      ]

      parent = self()

      log =
        capture_log(fn ->
          Req.Test.expect(MetricsPusher, 1, fn conn ->
            send(parent, :req_called)
            Conn.send_resp(conn, 500, "")
          end)

          {:ok, pid} = start_and_allow_pusher(opts)
          assert_receive :req_called, 300
          assert Process.alive?(pid)
          # Wait enough for the log to be captured
          Process.sleep(100)
        end)

      assert log =~ "MetricsPusher: Failed to push"
      assert log =~ "metrics to"
    end

    test "when an error is raised" do
      opts = [
        url: "https://example.com:8428/api/v1/import/prometheus",
        timeout: 5000
      ]

      parent = self()

      log =
        capture_log(fn ->
          Req.Test.expect(MetricsPusher, 1, fn _conn ->
            send(parent, :req_called)
            raise RuntimeError, "unexpected error"
          end)

          {:ok, pid} = start_and_allow_pusher(opts)
          assert_receive :req_called, 300
          assert Process.alive?(pid)
          # Wait enough for the log to be captured
          Process.sleep(100)
        end)

      assert log =~ "MetricsPusher: Exception during"
      assert log =~ "push: %RuntimeError{message: \"unexpected error\"}"
    end

    test "appends extra_label query params to URL" do
      opts = [
        url: "http://localhost:8428/api/v1/import/prometheus",
        compress: false,
        timeout: 5000,
        extra_labels: [{"region", "us-east-1"}, {"env", "prod"}]
      ]

      parent = self()

      Req.Test.expect(MetricsPusher, 1, fn conn ->
        send(parent, {:req_called, conn.query_string})
        Req.Test.text(conn, "")
      end)

      {:ok, _pid} = start_and_allow_pusher(opts)
      assert_receive {:req_called, query_string}, 300

      decoded_params = query_string |> String.split("&") |> Enum.map(&URI.decode_www_form/1)
      assert "extra_label=region=us-east-1" in decoded_params
      assert "extra_label=env=prod" in decoded_params
    end

    test "logs unexpected messages and stays alive" do
      parent = self()

      Req.Test.expect(MetricsPusher, 1, fn conn ->
        send(parent, :push_happened)
        Req.Test.text(conn, "")
      end)

      {:ok, pid} =
        start_and_allow_pusher(
          url: "http://localhost:8428/api/v1/import/prometheus",
          timeout: 5000
        )

      assert_receive :push_happened, 500

      log =
        capture_log(fn ->
          send(pid, :unexpected_message)
          Process.sleep(50)
          assert Process.alive?(pid)
        end)

      assert log =~ "MetricsPusher received unexpected message: :unexpected_message"
    end
  end
end
