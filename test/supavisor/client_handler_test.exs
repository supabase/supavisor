defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true
  require Supavisor

  alias Supavisor.Protocol.FrontendMessageHandler
  alias Supavisor.Protocol.MessageStreamer

  @subject Supavisor.ClientHandler

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

  describe "ban check" do
    alias Supavisor.ClientHandler.Checks
    alias Supavisor.Errors.TenantBannedError
    alias Supavisor.Tenants.Tenant

    test "returns :ok when tenant is not banned" do
      info = %{tenant: %Tenant{banned_at: nil, ban_reason: nil}}
      assert :ok = Checks.check_tenant_not_banned(info)
    end

    test "returns TenantBannedError for a permanent ban (banned_until nil)" do
      info = %{
        tenant: %Tenant{
          banned_at: ~U[2026-01-01 00:00:00Z],
          ban_reason: "abuse",
          banned_until: nil
        }
      }

      assert {:error, %TenantBannedError{ban_reason: "abuse"}} =
               Checks.check_tenant_not_banned(info)
    end

    test "returns TenantBannedError when banned_until is in the future" do
      future = DateTime.utc_now() |> DateTime.add(3600, :second)

      info = %{
        tenant: %Tenant{
          banned_at: ~U[2026-01-01 00:00:00Z],
          ban_reason: "abuse",
          banned_until: future
        }
      }

      assert {:error, %TenantBannedError{ban_reason: "abuse"}} =
               Checks.check_tenant_not_banned(info)
    end

    test "returns :ok when banned_until is in the past (ban expired)" do
      past = DateTime.utc_now() |> DateTime.add(-3600, :second)

      info = %{
        tenant: %Tenant{
          banned_at: ~U[2026-01-01 00:00:00Z],
          ban_reason: "abuse",
          banned_until: past
        }
      }

      assert :ok = Checks.check_tenant_not_banned(info)
    end

    test "TenantBannedError produces a FATAL postgres error message" do
      error = %TenantBannedError{ban_reason: "billing"}
      postgres_error = TenantBannedError.postgres_error(error)
      assert postgres_error["S"] == "FATAL"
      assert postgres_error["M"] =~ "EBANNED"
      assert postgres_error["M"] =~ "billing"
    end
  end

  describe "startup packet log_level option" do
    test "sets process log level from options" do
      bin =
        <<79::32,
          "\x00\x03\x00\x00user\x00postgres.dev_tenant\x00database\x00postgres\x00options\x00-c log_level=debug\x00\x00">>

      data = %{sock: {:gen_tcp, :fake_port}, id: "test", app_name: nil}

      assert {:keep_state, %{app_name: ""},
              {:next_event, :internal,
               {:hello, {:single, {"postgres", "dev_tenant", "postgres", nil, false, nil}}}}} =
               @subject.handle_event(:info, {:tcp, :fake_port, bin}, :handshake, data)

      assert Logger.get_process_level(self()) == :debug
    end
  end

  describe "handle_event/4 :busy ReadyForQuery expectation" do
    test "forwards the expected ReadyForQuery count to the DbHandler in transaction mode" do
      {db_sock, _recv} = sockpair()

      data = %{
        mode: :transaction,
        db_connection: {:pool, self(), {:gen_tcp, db_sock}},
        tenant_feature_flags: %{},
        stream_state: MessageStreamer.new_stream_state(FrontendMessageHandler)
      }

      # Three pipelined simple queries produce three ReadyForQuery replies.
      batch =
        <<?Q, 12::32, "SELECT 1">> <> <<?Q, 12::32, "SELECT 2">> <> <<?Q, 12::32, "SELECT 3">>

      assert {:keep_state, _data} =
               @subject.handle_event(:info, {:tcp, :sock, batch}, :busy, data)

      assert_received {:"$gen_cast", {:expect_ready_for_query, 3}}
    end

    test "does not send an expectation in session mode" do
      {db_sock, _recv} = sockpair()

      data = %{
        mode: :session,
        db_connection: {:pool, self(), {:gen_tcp, db_sock}},
        tenant_feature_flags: %{},
        stream_state: MessageStreamer.new_stream_state(FrontendMessageHandler)
      }

      batch = <<?Q, 12::32, "SELECT 1">> <> <<?Q, 12::32, "SELECT 2">>

      assert {:keep_state, _data} =
               @subject.handle_event(:info, {:tcp, :sock, batch}, :busy, data)

      refute_received {:"$gen_cast", {:expect_ready_for_query, _count}}
    end
  end

  describe "cancel query handling" do
    alias Supavisor.ClientHandler.Cancel

    setup do
      case start_supervised({Phoenix.PubSub, name: Supavisor.PubSub}) do
        {:ok, _} -> :ok
        {:error, {:already_started, _}} -> :ok
      end
    end

    test "handles {:cancel_query, from_pid, ref} and sends cancel_ack in idle state" do
      ref = make_ref()
      data = %{tenant: "test_tenant", db_connection: nil}

      assert :keep_state_and_data =
               @subject.handle_event(:info, {:cancel_query, self(), ref}, :idle, data)

      assert_received {:cancel_ack, ^ref}
    end

    test "handles legacy :cancel_query atom message in idle state" do
      data = %{tenant: "test_tenant", db_connection: nil}

      assert :keep_state_and_data =
               @subject.handle_event(:info, :cancel_query, :idle, data)
    end

    test "two-phase commit: busy owner claims, sender grants, DbHandler cancels and acks" do
      ref = make_ref()
      test_pid = self()

      # Mock DbHandler process that handles cancel_query call
      mock_db =
        spawn_link(fn ->
          receive do
            {:"$gen_call", from, {:cancel_query, caller_pid}} ->
              send(test_pid, {:db_cancelled, caller_pid})
              :gen_statem.reply(from, :ok)
          end
        end)

      data = %{
        tenant: "test_tenant",
        db_connection: {:pool, mock_db, {:gen_tcp, :fake_sock}}
      }

      # Run handle_event in a task (it will send claim and block until grant)
      handler_task =
        Task.async(fn ->
          @subject.handle_event(:info, {:cancel_query, test_pid, ref}, :busy, data)
        end)

      # 1. Owner claims authorization before contacting DbHandler
      assert_receive {:cancel_claim, owner_pid, ^ref}
      # Assert DbHandler has NOT been contacted before grant
      refute_received {:db_cancelled, _}

      # 2. Sender issues grant
      send(owner_pid, {:cancel_granted, ref})

      # 3. DbHandler receives cancel call after grant
      assert_receive {:db_cancelled, ^owner_pid}

      # 4. Sender receives ack
      assert_receive {:cancel_ack, ^ref}

      # 5. Handler completes cleanly
      assert :keep_state_and_data = Task.await(handler_task, 2_000)
    end

    test "expired sender production path: delayed request to busy handler causes ZERO backend cancellation" do
      ref = make_ref()
      test_pid = self()

      # Spawn a temporary sender that terminates immediately (simulating an expired cancel request)
      dead_sender =
        spawn(fn ->
          :ok
        end)

      # Wait for sender to fully exit
      mref = Process.monitor(dead_sender)
      assert_receive {:DOWN, ^mref, :process, ^dead_sender, :normal}

      mock_db =
        spawn_link(fn ->
          receive do
            {:"$gen_call", _from, {:cancel_query, _caller_pid}} ->
              send(test_pid, :unexpected_db_cancel)
          end
        end)

      data = %{
        tenant: "test_tenant",
        db_connection: {:pool, mock_db, {:gen_tcp, :fake_sock}}
      }

      # Deliver delayed cancel request from dead sender to busy ClientHandler
      assert :keep_state_and_data =
               @subject.handle_event(:info, {:cancel_query, dead_sender, ref}, :busy, data)

      # Assert ZERO backend cancellation occurs!
      refute_received :unexpected_db_cancel
    end

    test "Cancel.send_cancel_query/3 grants claim, holds sender until DbHandler completes, and returns on ack" do
      pid = 1111
      key = 2222
      topic = "cancel_req:#{pid}_#{key}"
      test_pid = self()

      sender_task = Task.async(fn -> Cancel.send_cancel_query(pid, key) end)

      _owner =
        spawn_link(fn ->
          Phoenix.PubSub.subscribe(Supavisor.PubSub, topic)
          send(test_pid, :subscriber_ready)

          receive do
            {:cancel_query, from_pid, ref} ->
              # 1. Claim
              send(from_pid, {:cancel_claim, self(), ref})

              # 2. Wait for grant
              receive do
                {:cancel_granted, ^ref} ->
                  send(test_pid, :grant_received)

                  # Hold cancellation in flight
                  receive do
                    :release_db ->
                      send(from_pid, {:cancel_ack, ref})
                      send(test_pid, :ack_sent)
                  end
              end
          end
        end)

      assert_receive :subscriber_ready
      assert_receive :grant_received

      # Sender must NOT exit while grant is active and ack has not arrived
      refute Task.yield(sender_task, 100)

      # Release backend cancellation
      send(_owner, :release_db)
      assert_receive :ack_sent

      # Sender completes on ack
      assert :ok = Task.await(sender_task, 2_000)
    end

    test "Cancel.send_cancel_query/3 releases cleanly when owner dies after grant" do
      pid = 5555
      key = 6666
      topic = "cancel_req:#{pid}_#{key}"
      test_pid = self()

      sender_task = Task.async(fn -> Cancel.send_cancel_query(pid, key) end)

      owner =
        spawn(fn ->
          Phoenix.PubSub.subscribe(Supavisor.PubSub, topic)
          send(test_pid, :subscriber_ready)

          receive do
            {:cancel_query, from_pid, ref} ->
              send(from_pid, {:cancel_claim, self(), ref})

              receive do
                {:cancel_granted, ^ref} ->
                  send(test_pid, :grant_received)
                  # Crash / terminate owner process after grant
                  exit(:simulated_owner_crash)
              end
          end
        end)

      assert_receive :subscriber_ready
      assert_receive :grant_received

      # Sender detects owner DOWN via monitor and releases cleanly without hanging
      assert :ok = Task.await(sender_task, 2_000)
    end

    test "Cancel.send_cancel_query/3 with custom message broadcasts without waiting" do
      pid = 3333
      key = 4444
      topic = "cancel_req:#{pid}_#{key}"
      Phoenix.PubSub.subscribe(Supavisor.PubSub, topic)

      assert :ok = Cancel.send_cancel_query(pid, key, :custom_cancel_message)
      assert_receive :custom_cancel_message
    end

    test "Cancel.send_cancel_query/3 handles timeout gracefully when no subscriber" do
      assert :ok = Cancel.send_cancel_query(9999, 9999, :custom_no_wait)
    end
  end
end
