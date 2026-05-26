defmodule Supavisor.DbHandlerCheckoutApiTest do
  @moduledoc """
  Tests for the `Supavisor.DbHandler.checkout/5` public API surface — in
  particular the `:caller_module` opt added so the HTTP /sql client can
  receive `db_status/2` callbacks without DbHandler being hard-coded to a
  single caller.

  We use a tiny `:gen_statem` stub that captures the checkout call tuple so
  we can assert exactly what `checkout/5` sends across the wire to the real
  DbHandler. Both opt-shapes (legacy integer timeout, new keyword list)
  must reach the gen_statem as the same `{:checkout, sock, caller,
  caller_module}` 4-tuple.
  """

  use ExUnit.Case, async: true

  defmodule CaptureStub do
    @moduledoc false
    @behaviour :gen_statem

    def start_link(parent), do: :gen_statem.start_link(__MODULE__, parent, [])
    def callback_mode, do: :handle_event_function
    def init(parent), do: {:ok, :idle, %{parent: parent}}

    def handle_event({:call, from}, {:checkout, _sock, _caller, _cm} = call, _state, data) do
      send(data.parent, {:got_checkout, call})
      {:keep_state, data, {:reply, from, {:ok, {:fake_sock, self()}}}}
    end

    def handle_event(:info, _, _, _), do: :keep_state_and_data
    def terminate(_, _, _), do: :ok
  end

  defp start_stub do
    {:ok, pid} = CaptureStub.start_link(self())
    on_exit(fn -> if Process.alive?(pid), do: :gen_statem.stop(pid) end)
    pid
  end

  describe "checkout/5 opt shapes" do
    test "default opts: caller_module defaults to Supavisor.ClientHandler" do
      stub = start_stub()
      sock = {:proc, self()}

      assert {:ok, {:fake_sock, ^stub}} =
               Supavisor.DbHandler.checkout(stub, sock, self(), :transaction)

      assert_receive {:got_checkout, {:checkout, ^sock, _caller, Supavisor.ClientHandler}}
    end

    test "legacy integer timeout still works (backwards-compat)" do
      stub = start_stub()
      sock = {:proc, self()}

      assert {:ok, _} = Supavisor.DbHandler.checkout(stub, sock, self(), :transaction, 5_000)

      assert_receive {:got_checkout, {:checkout, ^sock, _caller, Supavisor.ClientHandler}}
    end

    test "keyword opts with :caller_module override" do
      stub = start_stub()
      sock = {:proc, self()}

      assert {:ok, _} =
               Supavisor.DbHandler.checkout(stub, sock, self(), :transaction,
                 timeout: 5_000,
                 caller_module: Supavisor.HttpSql.ClientHandler
               )

      assert_receive {:got_checkout,
                      {:checkout, ^sock, _caller, Supavisor.HttpSql.ClientHandler}}
    end

    test "keyword opts with :timeout only (no caller_module) still defaults the module" do
      stub = start_stub()
      sock = {:proc, self()}

      assert {:ok, _} =
               Supavisor.DbHandler.checkout(stub, sock, self(), :transaction, timeout: 5_000)

      assert_receive {:got_checkout, {:checkout, ^sock, _caller, Supavisor.ClientHandler}}
    end
  end

  describe "checkout/5 error wrapping" do
    defmodule NoReplyStub do
      @moduledoc false
      @behaviour :gen_statem
      def start_link, do: :gen_statem.start_link(__MODULE__, nil, [])
      def callback_mode, do: :handle_event_function
      def init(_), do: {:ok, :idle, nil}
      # Postpone every call forever — caller-side timeout will fire.
      def handle_event({:call, _from}, _, _, _), do: {:keep_state_and_data, :postpone}
      def handle_event(_, _, _, _), do: :keep_state_and_data
      def terminate(_, _, _), do: :ok
    end

    test "timeout on call → CheckoutTimeoutError" do
      {:ok, noreply} = NoReplyStub.start_link()
      on_exit(fn -> if Process.alive?(noreply), do: :gen_statem.stop(noreply) end)

      assert {:error, %Supavisor.Errors.CheckoutTimeoutError{timeout_ms: 50}} =
               Supavisor.DbHandler.checkout(noreply, {:proc, self()}, self(), :transaction,
                 timeout: 50
               )
    end

    test "dead stub → DbHandlerExitedError" do
      stub = start_stub()
      :gen_statem.stop(stub)
      # stub pid is now dead

      assert {:error, %Supavisor.Errors.DbHandlerExitedError{reason: :noproc}} =
               Supavisor.DbHandler.checkout(stub, {:proc, self()}, self(), :transaction)
    end
  end
end
