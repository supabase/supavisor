defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  @subject Supavisor.ClientHandler

  describe "TLS alert handling" do
    setup do
      sock =
        {:sslsocket,
         {
           :gen_tcp,
           :some_port,
           :tls_connection,
           [session_id_tracker: :some_pid]
         }, [:some_pid]}

      data = %{sock: {:ssl, sock}}
      {:ok, sock: sock, data: data}
    end

    test "handles fatal TLS alert by terminating", %{sock: sock, data: data} do
      error =
        {:ssl_error, sock,
         {
           :tls_alert,
           {:user_canceled,
            ~c"TLS server: In state connection received CLIENT ALERT: Fatal - User Canceled\n"}
         }}

      assert {:stop, :normal} == @subject.handle_event(:info, error, nil, data)
    end

    test "handles warning TLS alert by keeping connection alive", %{sock: sock, data: data} do
      error =
        {:ssl_error, sock,
         {
           :tls_alert,
           {:close_notify,
            ~c"TLS server: In state connection received CLIENT ALERT: Warning - Close Notify\n"}
         }}

      assert :keep_state_and_data == @subject.handle_event(:info, error, nil, data)
    end

    test "handles non-alert SSL errors by keeping state", %{sock: sock, data: data} do
      error = {:ssl_error, sock, :some_other_reason}

      assert :keep_state_and_data == @subject.handle_event(:info, error, nil, data)
    end
  end
end
