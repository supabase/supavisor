defmodule Supavisor.ClientHandler.ConnectionRequestTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler.{ConnectionRequest, Error}
  alias Supavisor.Errors

  @event [:supavisor, :client, :connection_request, :stop]

  setup do
    test_pid = self()
    ref = make_ref()
    handler_id = {__MODULE__, ref}

    :telemetry.attach(
      handler_id,
      @event,
      fn _event, measurements, metadata, _config ->
        # Handlers are global: ignore events emitted by other tests' processes
        if self() == test_pid, do: send(test_pid, {ref, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    data = %{connection_start: System.monotonic_time(), mode: :session, local: false}
    %{ref: ref, data: data}
  end

  describe "ok/1" do
    test "records a success with empty error labels", %{ref: ref, data: data} do
      assert :ok = ConnectionRequest.ok(data)

      assert_receive {^ref, %{duration: duration}, metadata}
      assert duration >= 0

      assert metadata == %{outcome: :ok, code: "", reason: "", fault: "", mode: :session}
    end
  end

  describe "error/2" do
    test "tags the failure with the code and fault of the exception", %{ref: ref, data: data} do
      ConnectionRequest.error(data, %Errors.WrongPasswordError{user: "u"})

      assert_receive {^ref, _, metadata}

      assert metadata == %{
               outcome: :error,
               code: "EWRONGPASSWORD",
               reason: "",
               fault: :user,
               mode: :session
             }
    end

    test "carries the reason for a checkout timeout", %{ref: ref, data: data} do
      ConnectionRequest.error(data, %Errors.CheckoutTimeoutError{reason: :unresponsive})

      assert_receive {^ref, _, %{code: "ECHECKOUTTIMEOUT", reason: :unresponsive, fault: fault}}
      assert fault == :supavisor
    end

    test "does not turn arbitrary reason fields into labels", %{ref: ref, data: data} do
      ConnectionRequest.error(data, %Errors.SslHandshakeError{reason: :closed})

      assert_receive {^ref, _, %{code: "ESSLHANDSHAKE", reason: ""}}
    end

    test "treats anything that is not an exception as our failure", %{ref: ref, data: data} do
      ConnectionRequest.error(data, :killed)

      assert_receive {^ref, _, %{code: "internal", fault: :supavisor, outcome: :error}}
    end
  end

  describe "a proxying handler" do
    setup %{data: data}, do: %{data: %{data | mode: :proxy}}

    test "does not record a success", %{ref: ref, data: data} do
      ConnectionRequest.ok(data)

      refute_receive {^ref, _, _}, 50
    end

    test "does not record an exit it did not classify", %{ref: ref, data: data} do
      ConnectionRequest.error(data, :normal)

      refute_receive {^ref, _, _}, 50
    end

    test "records an error it classified itself", %{ref: ref, data: data} do
      ConnectionRequest.error(data, Errors.MaxConnectionsError.new(:proxy, 10))

      assert_receive {^ref, _,
                      %{outcome: :error, code: "EMAXCONN", fault: :user_timeout, mode: :proxy}}
    end

    test "the process exit after the pool node failed it adds nothing", %{ref: ref, data: data} do
      assert :ok = Supavisor.ClientHandler.terminate(:normal, :connecting, data)

      refute_receive {^ref, _, _}, 50
    end
  end

  describe "terminate/3 safety net" do
    test "records a crash before greetings as our failure", %{ref: ref, data: data} do
      Supavisor.ClientHandler.terminate({:badmatch, :boom}, :handshake, data)

      assert_receive {^ref, _, %{outcome: :error, code: "internal", fault: :supavisor}}
    end

    test "adds nothing after an outcome was recorded", %{ref: ref, data: data} do
      ConnectionRequest.ok(data)
      assert_receive {^ref, _, %{outcome: :ok}}

      Supavisor.ClientHandler.terminate(:normal, :idle, data)

      refute_receive {^ref, _, _}, 50
    end
  end

  describe "exactly once" do
    test "a second outcome is not recorded", %{ref: ref, data: data} do
      ConnectionRequest.ok(data)
      ConnectionRequest.error(data, %Errors.WrongPasswordError{user: "u"})
      ConnectionRequest.ok(data)

      assert_receive {^ref, _, %{outcome: :ok}}
      refute_receive {^ref, _, _}, 50
    end

    test "ignore/0 suppresses the outcome", %{ref: ref, data: data} do
      ConnectionRequest.ignore()
      ConnectionRequest.error(data, :normal)

      refute_receive {^ref, _, _}, 50
    end

    test "pending?/0 flips once an outcome is recorded", %{data: data} do
      assert ConnectionRequest.pending?()
      ConnectionRequest.ok(data)
      refute ConnectionRequest.pending?()
    end
  end

  describe "Error.terminate_with_error/3" do
    test "records the failure once, before anything is sent to the client", %{
      ref: ref,
      data: data
    } do
      {client, server} = sockpair()
      test_pid = self()

      # Runs inside terminate_with_error, so it sees whether the error response went out yet
      :telemetry.attach(
        {__MODULE__, :ordering, ref},
        @event,
        fn _event, _measurements, _metadata, _config ->
          if self() == test_pid, do: send(test_pid, {:sent_yet, :gen_tcp.recv(client, 0, 0)})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach({__MODULE__, :ordering, ref}) end)

      data = Map.merge(data, %{sock: {:gen_tcp, server}, id: nil})

      assert {:stop, :normal} =
               Error.terminate_with_error(data, %Errors.WrongPasswordError{user: "u"}, :handshake)

      assert_receive {:sent_yet, {:error, :timeout}}
      assert_receive {^ref, _, %{code: "EWRONGPASSWORD", fault: :user}}
      refute_receive {^ref, _, _}, 50

      assert {:ok, response} = :gen_tcp.recv(client, 0, 1_000)
      assert response =~ "password authentication failed"
    end

    test "does not record an error after greetings were sent", %{ref: ref, data: data} do
      {_client, server} = sockpair()
      data = Map.merge(data, %{sock: {:gen_tcp, server}, id: nil})

      ConnectionRequest.ok(data)
      assert_receive {^ref, _, %{outcome: :ok}}

      Error.terminate_with_error(
        data,
        %Errors.DbHandlerExitedError{reason: :boom},
        :authenticated
      )

      refute_receive {^ref, _, _}, 50
    end

    test "records pre-greeting failures reported with the :authenticated context", %{
      ref: ref,
      data: data
    } do
      {_client, server} = sockpair()
      data = Map.merge(data, %{sock: {:gen_tcp, server}, id: nil})

      # proxy mode connect_db failures take this path before greetings
      Error.terminate_with_error(
        data,
        %Errors.DbHandlerExitedError{reason: :boom},
        :authenticated
      )

      assert_receive {^ref, _, %{outcome: :error, code: "EDBHANDLEREXITED", fault: :supavisor}}
    end
  end

  defp sockpair do
    {:ok, listen} = :gen_tcp.listen(0, mode: :binary, active: false)
    {:ok, {address, port}} = :inet.sockname(listen)
    this = self()
    ref = make_ref()

    spawn(fn ->
      {:ok, recv} = :gen_tcp.accept(listen)
      :gen_tcp.controlling_process(recv, this)
      send(this, {ref, recv})
    end)

    {:ok, send} = :gen_tcp.connect(address, port, mode: :binary, active: false)
    assert_receive {^ref, recv}

    {send, recv}
  end
end
