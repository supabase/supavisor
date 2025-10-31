defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  @subject Supavisor.ClientHandler

  test "handle ssl_error" do
    sock =
      {:sslsocket,
       {
         :gen_tcp,
         :some_port,
         :tls_connection,
         [session_id_tracker: :some_pid]
       }, [:some_pid]}

    error =
      {:ssl_error, sock,
       {
         :tls_alert,
         {:user_canceled,
          ~c"TLS server: In state connection received CLIENT ALERT: Fatal - User Canceled\n"}
       }}

    data = %{sock: {:ssl, sock}}

    assert :keep_state_and_data ==
             @subject.handle_event(:info, error, nil, data)
  end

  test "applies requested log level from startup payload" do
    :meck.expect(Supavisor.Helpers, :set_log_level, fn level ->
      send(self(), {:set_log_level, level})
      :ok
    end)

    hello = %{payload: %{"options" => %{"log_level" => "notice"}}}

    try do
      capture_log(fn ->
        assert @subject.maybe_change_log(hello) == :notice
      end)

      assert_received {:set_log_level, :notice}
    after
      :meck.unload(Supavisor.Helpers)
    end
  end
end
