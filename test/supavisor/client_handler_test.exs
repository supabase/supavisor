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
      state = :idle

      assert {:ok, ^state, ^old_data} =
               @subject.code_change("1.0", state, old_data, :monitor_socket)
    end

    test "monitor leaves data unchanged when sock format is unrecognized" do
      old_data = %{sock: :unexpected_format}
      state = :busy

      assert {:ok, ^state, ^old_data} =
               @subject.code_change("1.0", state, old_data, :monitor_socket)
    end

    test "demonitors port for plain TCP connections" do
      {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false])
      {:ok, {address, port}} = :inet.sockname(listen)

      start_supervised(
        {Task,
         fn ->
           {:ok, _socket} = :gen_tcp.accept(listen)
         end}
      )

      {:ok, tcp_socket} = :gen_tcp.connect(address, port, [:binary, active: false])

      ref = Port.monitor(tcp_socket)
      data = %{sock: {:gen_tcp, tcp_socket}, sock_ref: {:port, ref}}

      assert {:monitors, [{:port, ^tcp_socket}]} = Process.info(self(), :monitors)

      assert {:ok, :idle, new_data} =
               @subject.code_change("1.0", :idle, data, :demonitor_socket)

      assert {:monitors, []} = Process.info(self(), :monitors)
      refute Map.has_key?(new_data, :sock_ref)
    end

    test "demonitors process for TLS connections" do
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

      {:sslsocket, _, [controller_pid | _]} = ssl_socket
      ref = Process.monitor(controller_pid)
      data = %{sock: {:ssl, ssl_socket}, sock_ref: {:process, ref}}

      assert {:monitors, [{:process, ^controller_pid}]} = Process.info(self(), :monitors)

      assert {:ok, :idle, new_data} =
               @subject.code_change("1.0", :idle, data, :demonitor_socket)

      assert {:monitors, []} = Process.info(self(), :monitors)
      refute Map.has_key?(new_data, :sock_ref)
    end

    test "demonitor leaves data unchanged when sock_ref is missing" do
      old_data = %{other_field: :value}
      state = :idle

      assert {:ok, ^state, ^old_data} =
               @subject.code_change("1.0", state, old_data, :demonitor_socket)
    end
  end
end
