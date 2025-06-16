defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

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
end
