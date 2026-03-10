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

  describe "socket DOWN handler" do
    test "handles DOWN message for matching ref" do
      ref = make_ref()
      data = %{sock_ref: ref, mode: :transaction}

      assert {:stop, :normal} =
               @subject.handle_event(:info, {:DOWN, ref, :port, self(), :normal}, :idle, data)
    end

    test "ignores DOWN message with non-matching ref" do
      ref = make_ref()
      other_ref = make_ref()
      data = %{sock_ref: ref}

      assert :keep_state_and_data =
               @subject.handle_event(
                 :info,
                 {:DOWN, other_ref, :port, self(), :normal},
                 :idle,
                 data
               )
    end
  end

  describe "startup packet log_level option" do
    test "sets process log level from options" do
      bin =
        <<79::32,
          "\x00\x03\x00\x00user\x00postgres.dev_tenant\x00database\x00postgres\x00options\x00-c log_level=debug\x00\x00">>

      data = %{sock: {:gen_tcp, :fake_port}, id: "test", app_name: nil}

      assert {:keep_state, %{app_name: "Supavisor"},
              {:next_event, :internal,
               {:hello, {:single, {"postgres", "dev_tenant", "postgres", nil}}}}} =
               @subject.handle_event(:info, {:tcp, :fake_port, bin}, :handshake, data)

      assert Logger.get_process_level(self()) == :debug
    end
  end
end
