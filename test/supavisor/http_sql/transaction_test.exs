defmodule Supavisor.HttpSql.TransactionTest do
  use ExUnit.Case, async: true

  @subject Supavisor.HttpSql.Transaction

  describe "build/1" do
    test "empty map → no SQL" do
      assert {:ok, nil} = @subject.build(%{})
    end

    test "all nils → no SQL" do
      assert {:ok, nil} =
               @subject.build(%{isolation: nil, read_only: nil, deferrable: nil})
    end

    test "ReadCommitted → ISOLATION LEVEL READ COMMITTED" do
      assert {:ok, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"} =
               @subject.build(%{isolation: "ReadCommitted"})
    end

    test "Serializable" do
      assert {:ok, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"} =
               @subject.build(%{isolation: "Serializable"})
    end

    test "RepeatableRead" do
      assert {:ok, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"} =
               @subject.build(%{isolation: "RepeatableRead"})
    end

    test "ReadUncommitted" do
      assert {:ok, "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED"} =
               @subject.build(%{isolation: "ReadUncommitted"})
    end

    test "case-insensitive isolation" do
      assert {:ok, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"} =
               @subject.build(%{isolation: "SERIALIZABLE"})
    end

    test "isolation with spaces gets normalized" do
      assert {:ok, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"} =
               @subject.build(%{isolation: "Repeatable Read"})
    end

    test "read_only=true → READ ONLY" do
      assert {:ok, "SET TRANSACTION READ ONLY"} = @subject.build(%{read_only: "true"})
    end

    test "read_only=false → READ WRITE" do
      assert {:ok, "SET TRANSACTION READ WRITE"} = @subject.build(%{read_only: "false"})
    end

    test "deferrable=true" do
      assert {:ok, "SET TRANSACTION DEFERRABLE"} = @subject.build(%{deferrable: "true"})
    end

    test "deferrable=false" do
      assert {:ok, "SET TRANSACTION NOT DEFERRABLE"} = @subject.build(%{deferrable: "false"})
    end

    test "all three combined in canonical order" do
      assert {:ok, sql} =
               @subject.build(%{
                 isolation: "Serializable",
                 read_only: "true",
                 deferrable: "true"
               })

      assert sql == "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"
    end

    test "rejects bogus isolation" do
      assert {:error, {:invalid_isolation, "ChaoticEvil"}} =
               @subject.build(%{isolation: "ChaoticEvil"})
    end

    test "rejects bogus read_only value" do
      assert {:error, {:invalid_read_only, "yes"}} = @subject.build(%{read_only: "yes"})
    end

    test "rejects bogus deferrable value" do
      assert {:error, {:invalid_deferrable, "1"}} = @subject.build(%{deferrable: "1"})
    end

    test "does not allow injection through isolation" do
      assert {:error, {:invalid_isolation, _}} =
               @subject.build(%{isolation: "Serializable; DROP TABLE users"})
    end
  end

  describe "from_headers/1" do
    test "picks out all three Neon-Batch-* headers" do
      headers = [
        {"content-type", "application/json"},
        {"neon-batch-isolation-level", "Serializable"},
        {"neon-batch-read-only", "true"},
        {"neon-batch-deferrable", "false"}
      ]

      assert %{isolation: "Serializable", read_only: "true", deferrable: "false"} =
               @subject.from_headers(headers)
    end

    test "missing headers → nil values" do
      assert %{isolation: nil, read_only: nil, deferrable: nil} = @subject.from_headers([])
    end

    test "empty-string header treated as missing" do
      assert %{isolation: nil} =
               @subject.from_headers([{"neon-batch-isolation-level", ""}])
    end
  end
end
