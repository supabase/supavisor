defmodule Supavisor.Protocol.FrontendMessageHandlerTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Supavisor.Asserts

  alias Supavisor.Protocol.FrontendMessageHandler
  alias Supavisor.Protocol.MessageStreamer

  require MessageStreamer

  setup do
    stream_state = MessageStreamer.new_stream_state(FrontendMessageHandler)

    {:ok, stream_state: stream_state}
  end

  describe "MessageStreamer integration" do
    test "unnamed prepared statements are passed through unchanged", %{
      stream_state: stream_state
    } do
      original_bin = <<?P, 16::32, 0, "select 1", 0, 0, 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state).prepared_statements ==
               MessageStreamer.stream_state(stream_state, :handler_state).prepared_statements

      assert result == [original_bin]
    end

    test "passthrough for message types we ignore", %{
      stream_state: stream_state
    } do
      # Execute message (should pass through)
      original_bin = <<?E, 9::32, 0, 0, 0, 0, 200>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [original_bin]
    end

    test "simple query with prepared statement commands returns error" do
      stream_state =
        MessageStreamer.new_stream_state(FrontendMessageHandler)
        |> with_simple_query_prepare_check()

      prepare_bin = <<?Q, 27::32, "PREPARE stmt AS SELECT 1">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, prepare_bin)

      assert_valid_error(error)

      execute_bin = <<?Q, 19::32, "EXECUTE stmt(1)">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, execute_bin)

      assert_valid_error(error)

      deallocate_bin = <<?Q, 19::32, "DEALLOCATE stmt">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, deallocate_bin)

      assert_valid_error(error)
    end

    test "regular simple query passes through unchanged", %{stream_state: stream_state} do
      original_bin = <<?Q, 12::32, "SELECT 1">>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state).prepared_statements ==
               MessageStreamer.stream_state(stream_state, :handler_state).prepared_statements

      assert result == [original_bin]
    end

    test "multiple statements with prepared statement commands returns error" do
      stream_state =
        MessageStreamer.new_stream_state(FrontendMessageHandler)
        |> with_simple_query_prepare_check()

      multi_query_bin = <<?Q, 36::32, "SELECT 1; PREPARE stmt AS SELECT 2">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, multi_query_bin)

      assert_valid_error(error)
    end

    test "prepared statement commands pass through when the check is disabled", %{
      stream_state: stream_state
    } do
      prepare_bin = simple_query("PREPARE stmt AS SELECT 1")

      assert {:ok, _, [^prepare_bin]} =
               MessageStreamer.handle_packets(stream_state, prepare_bin)
    end

    test "multiple allowed statements pass through unchanged", %{stream_state: stream_state} do
      multi_query_bin = <<?Q, 32::32, "SELECT 1; SELECT 2; SELECT 3">>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, multi_query_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state).prepared_statements ==
               MessageStreamer.stream_state(stream_state, :handler_state).prepared_statements

      assert result == [multi_query_bin]
    end
  end

  defp with_set_statements_action(stream_state, action) do
    MessageStreamer.update_state(stream_state, &%{&1 | set_statements_action: action})
  end

  defp with_simple_query_prepare_check(stream_state) do
    MessageStreamer.update_state(stream_state, &%{&1 | check_simple_query_prepare?: true})
  end

  defp simple_query(query) do
    <<?Q, byte_size(query) + 5::32, query::binary, 0>>
  end

  defp parse_message(query) do
    <<?P, byte_size(query) + 8::32, 0, query::binary, 0, 0::16>>
  end

  describe "SET statements in transaction mode" do
    test "ignore action passes SET through silently", %{stream_state: stream_state} do
      bin = simple_query("SET statement_timeout = '1s'")

      log =
        capture_log(fn ->
          assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
        end)

      refute log =~ "SET statement"
    end

    test "log action logs a warning and passes SET through", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :log)
      bin = simple_query("SET statement_timeout = '1s'")

      log =
        capture_log(fn ->
          assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
        end)

      assert log =~
               "received session-level SET statement in transaction mode: SET statement_timeout = '1s'"
    end

    test "log action detects SET in Parse messages", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :log)
      bin = parse_message("SET statement_timeout = '1s'")

      log =
        capture_log(fn ->
          assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
        end)

      assert log =~
               "received session-level SET statement in transaction mode: SET statement_timeout = '1s'"
    end

    test "log action ignores transaction-scoped SET variants", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :log)

      for query <- [
            "SET LOCAL statement_timeout = '1s'",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            "SELECT 1"
          ] do
        bin = simple_query(query)

        log =
          capture_log(fn ->
            assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
          end)

        refute log =~ "SET statement"
      end
    end

    test "error action returns an error on simple query", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)
      bin = simple_query("SET statement_timeout = '1s'")

      assert {:error, %Supavisor.Errors.SessionLeakError{leak: :session_set}} =
               error = MessageStreamer.handle_packets(stream_state, bin)

      assert_valid_error(error)
    end

    test "error action returns an error on Parse message", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)
      bin = parse_message("SET statement_timeout = '1s'")

      assert {:error, %Supavisor.Errors.SessionLeakError{leak: :session_set}} =
               error = MessageStreamer.handle_packets(stream_state, bin)

      assert_valid_error(error)
    end

    test "error action detects SET in multi-statement simple queries", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)
      bin = simple_query("SELECT 1; SET statement_timeout = '1s'")

      assert {:error, %Supavisor.Errors.SessionLeakError{leak: :session_set}} =
               error = MessageStreamer.handle_packets(stream_state, bin)

      assert_valid_error(error)
    end

    test "error action passes transaction-scoped SET variants through", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- [
            "SET LOCAL statement_timeout = '1s'",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            "BEGIN; SET LOCAL statement_timeout = '1s'; COMMIT"
          ] do
        bin = simple_query(query)
        assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
      end
    end

    test "error action applies when translation is disabled", %{stream_state: stream_state} do
      stream_state =
        MessageStreamer.update_state(
          stream_state,
          &%{&1 | translate?: false, set_statements_action: :error}
        )

      bin = simple_query("SET statement_timeout = '1s'")

      assert {:error, %Supavisor.Errors.SessionLeakError{leak: :session_set}} =
               error = MessageStreamer.handle_packets(stream_state, bin)

      assert_valid_error(error)
    end
  end

  # Statements other than a bare SET that also outlive the transaction and so
  # leak state onto a backend the client will not get back.
  describe "other session-poisoning statements" do
    test "set_config with is_local=false is an equivalent of SET", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- [
            "SELECT set_config('statement_timeout', '0', false)",
            "SELECT set_config('search_path', 'public', FALSE)",
            "SELECT pg_catalog.set_config('statement_timeout', '0', false)"
          ] do
        bin = simple_query(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: :set_config}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "set_config with is_local=true is transaction-scoped and allowed", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- [
            "SELECT set_config('statement_timeout', '0', true)",
            "SELECT set_config('statement_timeout', '0', TRUE)"
          ] do
        bin = simple_query(query)
        assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
      end
    end

    test "DISCARD wipes backend state, including our prepared statement cache", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- ["DISCARD ALL", "DISCARD PLANS", "DISCARD SEQUENCES", "DISCARD TEMP"] do
        bin = simple_query(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: :discard}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "session-scoped advisory locks are held on a backend the client loses", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- [
            "SELECT pg_advisory_lock(1)",
            "SELECT pg_advisory_lock_shared(1)",
            "SELECT pg_try_advisory_lock(1)",
            "SELECT pg_advisory_unlock_all()"
          ] do
        bin = simple_query(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: :advisory_lock}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "xact-scoped advisory locks are released on commit and allowed", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- [
            "SELECT pg_advisory_xact_lock(1)",
            "SELECT pg_try_advisory_xact_lock(1)"
          ] do
        bin = simple_query(query)
        assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
      end
    end

    test "LISTEN/UNLISTEN register notifications the client will never receive", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- ["LISTEN chan", "UNLISTEN chan", "UNLISTEN *"] do
        bin = simple_query(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: :listen}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "WITH HOLD cursors survive commit and stay open on the backend", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)
      bin = simple_query("DECLARE c CURSOR WITH HOLD FOR SELECT 1")

      assert {:error, %Supavisor.Errors.SessionLeakError{leak: :hold_cursor}} =
               error = MessageStreamer.handle_packets(stream_state, bin)

      assert_valid_error(error)
    end

    test "temp tables live for the lifetime of the backend connection", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)

      for query <- [
            "CREATE TEMP TABLE t (a int)",
            "CREATE TEMPORARY TABLE t (a int)",
            "CREATE TEMP TABLE t ON COMMIT PRESERVE ROWS AS SELECT 1"
          ] do
        bin = simple_query(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: :temp_table}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "ON COMMIT DROP temp tables do not outlive the transaction", %{
      stream_state: stream_state
    } do
      stream_state = with_set_statements_action(stream_state, :error)
      bin = simple_query("CREATE TEMP TABLE t ON COMMIT DROP AS SELECT 1")

      assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
    end

    test "SET CONSTRAINTS outside a transaction is session-scoped", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)
      bin = simple_query("SET CONSTRAINTS ALL DEFERRED")

      assert {:error, %Supavisor.Errors.SessionLeakError{leak: :set_constraints}} =
               error = MessageStreamer.handle_packets(stream_state, bin)

      assert_valid_error(error)
    end

    test "LOAD attaches a module to the session", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)
      bin = simple_query("LOAD 'auto_explain'")

      assert {:error, %Supavisor.Errors.SessionLeakError{leak: :load}} =
               error = MessageStreamer.handle_packets(stream_state, bin)

      assert_valid_error(error)
    end

    test "detected on the Parse path too, not just simple query", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)

      for {query, leak} <- [
            {"SELECT set_config('statement_timeout', '0', false)", :set_config},
            {"DISCARD ALL", :discard},
            {"SELECT pg_advisory_lock(1)", :advisory_lock},
            {"LISTEN chan", :listen}
          ] do
        bin = parse_message(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: ^leak}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "detected when buried in a multi-statement simple query", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)

      for {query, leak} <- [
            {"SELECT 1; SELECT set_config('statement_timeout', '0', false)", :set_config},
            {"SELECT 1; DISCARD ALL", :discard},
            {"SELECT 1; LISTEN chan", :listen}
          ] do
        bin = simple_query(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: ^leak}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "reports the first leak when a query has several", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :error)

      for {query, leak} <- [
            {"DISCARD ALL; LISTEN chan", :discard},
            {"LISTEN chan; DISCARD ALL", :listen},
            {"SELECT 1; LOAD 'auto_explain'; DISCARD ALL", :load}
          ] do
        bin = simple_query(query)

        assert {:error, %Supavisor.Errors.SessionLeakError{leak: ^leak}} =
                 error = MessageStreamer.handle_packets(stream_state, bin)

        assert_valid_error(error)
      end
    end

    test "log action warns instead of erroring", %{stream_state: stream_state} do
      stream_state = with_set_statements_action(stream_state, :log)
      bin = simple_query("DISCARD ALL")

      log =
        capture_log(fn ->
          assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
        end)

      assert log =~ "DISCARD ALL"
    end

    test "ignore action passes them through silently", %{stream_state: stream_state} do
      for query <- [
            "SELECT set_config('statement_timeout', '0', false)",
            "DISCARD ALL",
            "SELECT pg_advisory_lock(1)",
            "LISTEN chan"
          ] do
        bin = simple_query(query)

        log =
          capture_log(fn ->
            assert {:ok, _, [^bin]} = MessageStreamer.handle_packets(stream_state, bin)
          end)

        refute log =~ "transaction mode"
      end
    end
  end

  # Frames `bin` and returns how many RFQ-producing messages the handler counted.
  defp rfq_producers(stream_state, bin) do
    {:ok, new_stream_state, _result} = MessageStreamer.handle_packets(stream_state, bin)
    MessageStreamer.stream_state(new_stream_state, :handler_state).rfq_producers
  end

  describe "ReadyForQuery-producer counting" do
    test "counts a simple query (Q)", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?Q, 12::32, "SELECT 1">>) == 1
    end

    test "counts a Sync (S)", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?S, 4::32>>) == 1
    end

    test "counts a FunctionCall (F)", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?F, 4::32>>) == 1
    end

    test "does not count Parse or Execute", %{stream_state: stream_state} do
      bin = <<?P, 16::32, 0, "select 1", 0, 0, 0>> <> <<?E, 9::32, 0, 0, 0, 0, 200>>
      assert rfq_producers(stream_state, bin) == 0
    end

    test "counts a multi-statement simple query as one producer", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?Q, 32::32, "SELECT 1; SELECT 2; SELECT 3">>) == 1
    end

    test "counts every query in a pipelined simple-query batch", %{stream_state: stream_state} do
      batch =
        <<?Q, 12::32, "SELECT 1">> <> <<?Q, 12::32, "SELECT 2">> <> <<?Q, 12::32, "SELECT 3">>

      assert rfq_producers(stream_state, batch) == 3
    end

    test "counts only the Sync in an extended-protocol batch", %{stream_state: stream_state} do
      bin =
        <<?P, 16::32, 0, "select 1", 0, 0, 0>> <>
          <<?E, 9::32, 0, 0, 0, 0, 200>> <>
          <<?S, 4::32>>

      assert rfq_producers(stream_state, bin) == 1
    end

    test "counts every Sync in a pipelined extended-protocol batch", %{stream_state: stream_state} do
      sequence =
        <<?P, 16::32, 0, "select 1", 0, 0, 0>> <>
          <<?E, 9::32, 0, 0, 0, 0, 200>> <>
          <<?S, 4::32>>

      assert rfq_producers(stream_state, sequence <> sequence) == 2
    end

    test "still counts (and forwards verbatim) when translation is disabled", %{
      stream_state: stream_state
    } do
      stream_state = MessageStreamer.update_state(stream_state, &%{&1 | translate?: false})
      sync = <<?S, 4::32>>

      {:ok, new_stream_state, result} = MessageStreamer.handle_packets(stream_state, sync)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state).rfq_producers == 1
      assert IO.iodata_to_binary(result) == sync
    end
  end
end
