defmodule Supavisor.PgParserTest do
  # async: false — the parse cache is global NIF state; stats assertions must
  # not run concurrently with other tests that call statement_types.
  use ExUnit.Case, async: false

  @subject Supavisor.PgParser

  doctest @subject

  describe "statement_types/1 classification" do
    test "classifies statement kinds" do
      cases = [
        {"SELECT 1", ["SelectStmt"]},
        {"select 1", ["SelectStmt"]},
        {"INSERT INTO t VALUES (1, 'a')", ["InsertStmt"]},
        {"UPDATE t SET a = 1 WHERE id = 2", ["UpdateStmt"]},
        {"DELETE FROM t WHERE id = 1", ["DeleteStmt"]},
        {"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", ["MergeStmt"]},
        {"WITH x AS (SELECT 1) SELECT * FROM x", ["SelectStmt"]},
        {"EXPLAIN SELECT 1", ["ExplainStmt"]},
        {"EXPLAIN ANALYZE UPDATE t SET a = 1", ["ExplainStmt"]},
        {"BEGIN", ["TransactionStmt"]},
        {"COMMIT", ["TransactionStmt"]},
        {"ROLLBACK", ["TransactionStmt"]},
        {"SET search_path = public", ["VariableSetStmt"]},
        {"PREPARE stmt AS SELECT $1", ["PrepareStmt"]},
        {"EXECUTE stmt(1)", ["ExecuteStmt"]},
        {"DEALLOCATE stmt", ["DeallocateStmt"]},
        {"DO $$ BEGIN END $$", ["DoStmt"]},
        {"COPY t FROM STDIN", ["CopyStmt"]},
        {"VACUUM t", ["VacuumStmt"]},
        {"SELECT 1; INSERT INTO t VALUES (1)", ["SelectStmt", "InsertStmt"]},
        {"SELECT * FROM t WHERE note = E'esc\\'aped'", ["SelectStmt"]},
        {"SELECT * FROM t WHERE \"идентификатор\" = 1", ["SelectStmt"]},
        {"SELECT * FROM t WHERE 名前 = '値'", ["SelectStmt"]},
        {"SELECT 1\r\n", ["SelectStmt"]},
        {"SELECT 1;", ["SelectStmt"]},
        {"SELECT 1;;", ["SelectStmt"]}
      ]

      for {sql, expected} <- cases do
        assert {:ok, types} = @subject.statement_types(sql)
        assert types == expected, "wrong classification for #{inspect(sql)}"
      end
    end

    test "empty and comment-only input parses to an empty list" do
      assert {:ok, []} = @subject.statement_types("")
      assert {:ok, []} = @subject.statement_types("-- only a comment\n")
      assert {:ok, []} = @subject.statement_types(";")
    end

    test "invalid SQL returns the contract error" do
      assert {:error, "Error parsing query"} = @subject.statement_types("not a valid sql")
      assert {:error, "Error parsing query"} = @subject.statement_types("SELECT FROM WHERE")
      assert {:error, "Error parsing query"} = @subject.statement_types("SELECT 'unterminated")
    end
  end

  describe "statements/1" do
    test "delegates to statement_types/1 for binaries" do
      assert {:ok, ["SelectStmt"]} = @subject.statements("SELECT 1")
    end

    test "rejects non-binaries" do
      assert {:error, "Query must be a string"} = @subject.statements(123)
      assert {:error, "Query must be a string"} = @subject.statements(nil)
    end
  end

  # Stats assertions use only exact identities that are independent of
  # scheduler migration:
  #   * the first call of a fresh shape must be a miss
  #   * bypass calls are counted exactly per call (independent of cache state)
  #   * for eligible calls: hits + misses == number of calls
  #   * inserts == entries + evictions (capacity identity)
  describe "shape cache accounting" do
    test "first call of a fresh shape is a miss, repeats become hits" do
      before = @subject.cache_stats()

      for _ <- 1..200 do
        assert {:ok, ["SelectStmt"]} =
                 @subject.statement_types("SELECT * FROM acct_repeat WHERE id = 1")
      end

      after_ = @subject.cache_stats()
      dhits = after_.hits - before.hits
      dmiss = after_.misses - before.misses

      assert dhits + dmiss == 200
      # each scheduler misses at most once for this shape
      assert dmiss >= 1
      assert dmiss <= :erlang.system_info(:schedulers_online)
    end

    test "literal values fold into one shape" do
      before = @subject.cache_stats()

      for n <- 1..200 do
        assert {:ok, ["SelectStmt"]} =
                 @subject.statement_types("SELECT * FROM acct_fold WHERE id = #{n}")
      end

      after_ = @subject.cache_stats()
      assert after_.hits + after_.misses - before.hits - before.misses == 200
      # constants fold: all 200 different literals share one shape
      assert after_.misses - before.misses <= :erlang.system_info(:schedulers_online)
    end

    test "allowlisted-but-invalid SQL never enters the cache" do
      before = @subject.cache_stats()

      for _ <- 1..50 do
        assert {:error, "Error parsing query"} =
                 @subject.statement_types("SELECT FROM WHERE acct_bad")
      end

      after_ = @subject.cache_stats()

      assert after_.parse_errors - before.parse_errors == 50
      assert after_.misses - before.misses == 50
      assert after_.inserts - before.inserts == 0
    end

    test "bypass families never hit or insert" do
      before = @subject.cache_stats()

      for _ <- 1..20 do
        assert {:ok, ["PrepareStmt"]} = @subject.statement_types("PREPARE acct_ps AS SELECT $1")
        assert {:ok, ["ExecuteStmt"]} = @subject.statement_types("EXECUTE acct_ps(1)")
        assert {:ok, ["DeallocateStmt"]} = @subject.statement_types("DEALLOCATE acct_ps")
        assert {:ok, ["TransactionStmt"]} = @subject.statement_types("BEGIN")
        assert {:ok, ["VariableSetStmt"]} = @subject.statement_types("SET search_path = public")
        assert {:ok, ["ExplainStmt"]} = @subject.statement_types("EXPLAIN SELECT 1")

        assert {:ok, ["SelectStmt"]} =
                 @subject.statement_types("WITH x AS (SELECT 1) SELECT * FROM x")

        assert {:ok, ["DoStmt"]} = @subject.statement_types("DO $$ BEGIN END $$")
      end

      after_ = @subject.cache_stats()

      assert after_.bypass_allowlist - before.bypass_allowlist == 8 * 20
      assert after_.inserts - before.inserts == 0
      assert after_.hits - before.hits == 0
    end

    test "multi-statement payloads bypass with their own counter" do
      before = @subject.cache_stats()

      for _ <- 1..20 do
        assert {:ok, ["SelectStmt", "SelectStmt"]} =
                 @subject.statement_types("SELECT 1; SELECT 2")

        assert {:ok, ["SelectStmt", "PrepareStmt"]} =
                 @subject.statement_types("SELECT 1; PREPARE acct_m AS SELECT 2")
      end

      after_ = @subject.cache_stats()

      assert after_.bypass_multi_statement - before.bypass_multi_statement == 40
      assert after_.inserts - before.inserts == 0
    end

    test "unicode literals bypass the cache and re-validate on every call" do
      # U&'...' bodies and the UESCAPE clause are validated by the parser's
      # token-filter layer, not the core scanner: two queries can share a
      # token shape yet differ in parse success, so they must never be
      # cached (regression: a cached valid shape must not absolve an
      # invalid one).
      valid = "SELECT U&'abc' UESCAPE '!'"
      invalid = "SELECT U&'abc' UESCAPE '0'"
      before = @subject.cache_stats()

      for _ <- 1..20 do
        # valid first, then invalid: the original poisoning order
        assert {:ok, ["SelectStmt"]} = @subject.statement_types(valid)
        assert {:error, "Error parsing query"} = @subject.statement_types(invalid)
        # and the reverse order
        assert {:error, "Error parsing query"} = @subject.statement_types(invalid)
        assert {:ok, ["SelectStmt"]} = @subject.statement_types(valid)
        # unicode escapes are validated even without a UESCAPE clause
        assert {:ok, ["SelectStmt"]} = @subject.statement_types("SELECT U&'\\0041'")
        assert {:error, "Error parsing query"} = @subject.statement_types("SELECT U&'\\q'")
      end

      after_ = @subject.cache_stats()

      assert after_.bypass_unsafe_literal - before.bypass_unsafe_literal == 6 * 20
      assert after_.hits - before.hits == 0
      assert after_.inserts - before.inserts == 0
      assert after_.parse_errors - before.parse_errors == 3 * 20
    end

    test "float(p) precision bypasses the cache and re-validates on every call" do
      # float(p) maps to float4/float8 in a raw-grammar action based on the
      # folded integer value (1..53 parses, 0 or 54+ errors), so
      # same-shape queries can differ in parse success.
      valid = "SELECT 1::float(53)"
      invalid = "SELECT 1::float(55)"
      before = @subject.cache_stats()

      for _ <- 1..20 do
        # valid first, then invalid, then the reverse order
        assert {:ok, ["SelectStmt"]} = @subject.statement_types(valid)
        assert {:error, "Error parsing query"} = @subject.statement_types(invalid)
        assert {:error, "Error parsing query"} = @subject.statement_types(invalid)
        assert {:ok, ["SelectStmt"]} = @subject.statement_types(valid)
        # the CAST form bypasses conservatively but parses fine
        assert {:ok, ["SelectStmt"]} = @subject.statement_types("SELECT CAST(1 AS float(8))")
      end

      after_ = @subject.cache_stats()

      assert after_.bypass_unsafe_literal - before.bypass_unsafe_literal == 5 * 20
      assert after_.hits - before.hits == 0
      assert after_.inserts - before.inserts == 0
      assert after_.parse_errors - before.parse_errors == 2 * 20
    end

    test "float without precision stays eligible for the cache" do
      before = @subject.cache_stats()

      for _ <- 1..50 do
        assert {:ok, ["SelectStmt"]} = @subject.statement_types("SELECT 1::float")
      end

      after_ = @subject.cache_stats()

      assert after_.bypass_unsafe_literal - before.bypass_unsafe_literal == 0
      assert after_.hits + after_.misses - before.hits - before.misses == 50
      assert after_.misses - before.misses <= :erlang.system_info(:schedulers_online)
    end

    test "eviction respects per-scheduler capacity" do
      before = @subject.cache_stats()
      unique = :erlang.system_info(:schedulers_online) * 128

      for n <- 1..unique do
        assert {:ok, ["SelectStmt"]} =
                 @subject.statement_types("SELECT * FROM acct_evict_#{n} WHERE id = 1")
      end

      after_ = @subject.cache_stats()
      dinserts = after_.inserts - before.inserts
      dentries = after_.entries - before.entries
      devictions = after_.evictions - before.evictions
      max_total = after_.max_entries * after_.schedulers

      assert dinserts == unique
      # capacity identity: inserts == entries + evictions
      assert dinserts == dentries + devictions
      # total entries are bounded (at most max_entries per scheduler)
      assert after_.entries <= max_total
      # unique shapes far exceed total capacity, so evictions must happen
      assert devictions > 0
    end

    test "concurrent same-shape calls stay consistent" do
      before = @subject.cache_stats()
      total = 1_000

      results =
        1..20
        |> Task.async_stream(
          fn _ ->
            for _ <- 1..50,
                do: @subject.statement_types("SELECT * FROM acct_conc WHERE id = 1")
          end,
          max_concurrency: 20,
          timeout: 30_000
        )
        |> Enum.flat_map(fn {:ok, rs} -> rs end)

      assert Enum.all?(results, &(&1 == {:ok, ["SelectStmt"]}))
      assert length(results) == total

      after_ = @subject.cache_stats()

      assert after_.hits + after_.misses - before.hits - before.misses == total
      assert after_.misses - before.misses <= :erlang.system_info(:schedulers_online)
    end

    test "concurrent unique-shape calls are all misses without corruption" do
      before = @subject.cache_stats()

      results =
        1..20
        |> Task.async_stream(
          fn task ->
            for n <- 1..50,
                do: @subject.statement_types("SELECT * FROM acct_u#{task}_#{n} WHERE id = 1")
          end,
          max_concurrency: 20,
          timeout: 30_000
        )
        |> Enum.flat_map(fn {:ok, rs} -> rs end)

      assert Enum.all?(results, &(&1 == {:ok, ["SelectStmt"]}))

      after_ = @subject.cache_stats()

      assert after_.misses - before.misses == 1_000
      assert after_.inserts - before.inserts == 1_000
    end
  end

  describe "shape corpus (differential)" do
    test "same-shape groups return identical results and share cache entries" do
      for group <- Supavisor.ParseShapeCorpus.same_shape_groups() do
        # results within a group are identical (a safety property,
        # independent of cache state)
        results = Enum.map(group, &@subject.statement_types/1)

        assert Enum.uniq(results) |> length() == 1,
               "same-shape group produced different results: #{inspect(group)}"

        # after repeated calls warm up every scheduler, hits dominate
        before = @subject.cache_stats()

        for _ <- 1..20, sql <- group do
          assert @subject.statement_types(sql) == hd(results)
        end

        after_ = @subject.cache_stats()
        total = 20 * length(group)

        assert after_.hits + after_.misses - before.hits - before.misses == total
        assert after_.misses - before.misses <= :erlang.system_info(:schedulers_online)
      end
    end

    test "distinct-shape pairs never hit each other's entry" do
      for {sql_a, sql_b} <- Supavisor.ParseShapeCorpus.distinct_shape_pairs() do
        before = @subject.cache_stats()

        {:ok, types_a} = @subject.statement_types(sql_a)
        {:ok, types_b} = @subject.statement_types(sql_b)

        after_ = @subject.cache_stats()

        # two fresh shapes: the first call of each must be a miss
        assert after_.misses - before.misses == 2
        assert after_.hits - before.hits == 0
        # results still match a direct parse
        assert {:ok, ^types_a} = @subject.statement_types(sql_a)
        assert {:ok, ^types_b} = @subject.statement_types(sql_b)
      end
    end
  end
end
