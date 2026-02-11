defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.Support.SSLHelper

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

  describe "code_change/4" do
    test "adds monitor for plain TCP connections" do
      {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false])
      {:ok, {address, port}} = :inet.sockname(listen)

      start_supervised(
        {Task,
         fn ->
           {:ok, _socket} = :gen_tcp.accept(listen)
         end}
      )

      {:ok, tcp_socket} = :gen_tcp.connect(address, port, [:binary, active: false])

      old_data = %{sock: {:gen_tcp, tcp_socket}}

      assert {:ok, :idle, new_data} =
               @subject.code_change("1.0", :idle, old_data, :monitor_socket)

      assert {:monitors, [{:port, ^tcp_socket}]} = Process.info(self(), :monitors)

      assert {:port, ref} = new_data.sock_ref
      assert is_reference(ref)

      assert new_data.sock == {:gen_tcp, tcp_socket}
    end

    test "adds monitor for TLS connections" do
      {:ok, cert_path, key_path} = SSLHelper.setup_test_ssl_certificates()
      {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false])
      {:ok, {address, port}} = :inet.sockname(listen)

      start_supervised(
        {Task,
         fn ->
           {:ok, tcp_client} = :gen_tcp.connect(address, port, [:binary, active: false])
           {:ok, _ssl_client} = :ssl.connect(tcp_client, verify: :verify_none, active: false)
         end}
      )

      {:ok, tcp_socket} = :gen_tcp.accept(listen)
      {:ok, ssl_socket} = :ssl.handshake(tcp_socket, certfile: cert_path, keyfile: key_path)

      old_data = %{sock: {:ssl, ssl_socket}}

      assert {:ok, :idle, new_data} =
               @subject.code_change("1.0", :idle, old_data, :monitor_socket)

      assert {:process, ref} = new_data.sock_ref
      assert is_reference(ref)
      assert new_data.sock == {:ssl, ssl_socket}
      assert {:monitors, [{:process, controller_pid}]} = Process.info(self(), :monitors)

      assert {:dictionary, dict} = Process.info(controller_pid, :dictionary)
      assert dict[:"$initial_call"] == {:ssl_gen_statem, :init, 1}
    end

    test "monitor leaves data unchanged when sock field is missing" do
      old_data = %{other_field: :value}

      assert {:ok, :busy, ^old_data} =
               @subject.code_change("1.0", :busy, old_data, :monitor_socket)
    end

    test "monitor leaves data unchanged when sock format is unrecognized" do
      old_data = %{sock: :unexpected_format}

      assert {:ok, :busy, ^old_data} =
               @subject.code_change("1.0", :busy, old_data, :monitor_socket)
    end
  end

  describe "socket DOWN handler" do
    test "handles DOWN message for port monitor" do
      ref = make_ref()
      data = %{sock_ref: {:port, ref}, mode: :transaction}

      assert {:stop, :normal} =
               @subject.handle_event(:info, {:DOWN, ref, :port, self(), :normal}, :idle, data)
    end

    test "handles DOWN message for process monitor" do
      ref = make_ref()
      data = %{sock_ref: {:process, ref}, mode: :transaction}

      assert {:stop, :normal} =
               @subject.handle_event(:info, {:DOWN, ref, :process, self(), :normal}, :idle, data)
    end

    test "ignores DOWN message with non-matching ref" do
      ref = make_ref()
      other_ref = make_ref()
      data = %{sock_ref: {:port, ref}}

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
        <<76::32,
          "\x00\x03\x00\x00user\x00postgres.dev_tenant\x00database\x00postgres\x00options\x00log_level=debug\x00\x00">>

      data = %{sock: {:gen_tcp, :fake_port}, id: "test", app_name: nil}

      assert {:keep_state, %{app_name: "Supavisor"},
              {:next_event, :internal,
               {:hello, {:single, {"postgres", "dev_tenant", "postgres", nil}}}}} =
               @subject.handle_event(:info, {:tcp, :fake_port, bin}, :handshake, data)

      assert Logger.get_process_level(self()) == :debug
    end
  end
end
