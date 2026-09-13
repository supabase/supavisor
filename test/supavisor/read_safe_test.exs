defmodule Supavisor.ReadSafeTest do
  use ExUnit.Case, async: true

  @subject Supavisor.ReadSafe

  describe "read_safe?/1 - pure reads" do
    test "plain SELECT" do
      assert @subject.read_safe?("SELECT 1")
    end

    test "SELECT with projection and WHERE" do
      assert @subject.read_safe?("SELECT id, email FROM users WHERE id = $1")
    end

    test "SELECT with ORDER BY and LIMIT" do
      assert @subject.read_safe?("SELECT * FROM users ORDER BY id LIMIT 10")
    end

    test "SELECT with JOIN" do
      assert @subject.read_safe?("SELECT * FROM a JOIN b ON a.id = b.a_id")
    end

    test "SELECT with subquery in WHERE" do
      assert @subject.read_safe?("SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)")
    end

    test "SELECT with read-only CTE" do
      assert @subject.read_safe?("WITH t AS (SELECT 1 AS n) SELECT * FROM t")
    end

    test "SELECT with nested read-only CTE" do
      assert @subject.read_safe?("""
             WITH wrapper AS (
               WITH body AS (SELECT 1 AS n)
               SELECT * FROM body
             )
             SELECT * FROM wrapper
             """)
    end

    test "UNION of two SELECTs" do
      assert @subject.read_safe?("SELECT 1 UNION SELECT 2")
    end

    test "INTERSECT of two SELECTs" do
      assert @subject.read_safe?("SELECT 1 INTERSECT SELECT 1")
    end

    test "EXCEPT of two SELECTs" do
      assert @subject.read_safe?("SELECT 1 EXCEPT SELECT 2")
    end

    test "SELECT with multiple read-only CTEs" do
      assert @subject.read_safe?("""
             WITH a AS (SELECT 1), b AS (SELECT 2)
             SELECT * FROM a, b
             """)
    end

    test "SELECT with CASE / CAST / COALESCE / BETWEEN" do
      assert @subject.read_safe?("""
             SELECT
               CASE WHEN status = 'paid' THEN total ELSE 0 END,
               COALESCE(nickname, name)::text
             FROM users
             WHERE id BETWEEN 1 AND 100
             """)
    end
  end

  describe "read_safe?/1 - non-select statements" do
    test "INSERT is unsafe" do
      refute @subject.read_safe?("INSERT INTO users VALUES (1, 'x')")
    end

    test "UPDATE is unsafe" do
      refute @subject.read_safe?("UPDATE users SET name = 'x' WHERE id = 1")
    end

    test "DELETE is unsafe" do
      refute @subject.read_safe?("DELETE FROM users WHERE id = 1")
    end

    test "SET (session scope) is unsafe" do
      refute @subject.read_safe?("SET statement_timeout = '5s'")
    end

    test "SET LOCAL (local scope) is unsafe" do
      refute @subject.read_safe?("SET LOCAL statement_timeout = '5s'")
    end

    test "RESET is unsafe" do
      refute @subject.read_safe?("RESET ALL")
    end

    test "LISTEN (session subscription)" do
      refute @subject.read_safe?("LISTEN channel")
    end

    test "CALL procedure" do
      refute @subject.read_safe?("CALL my_proc(1)")
    end

    test "CREATE TABLE is unsafe" do
      refute @subject.read_safe?("CREATE TABLE foo (id int)")
    end

    test "DROP TABLE is unsafe" do
      refute @subject.read_safe?("DROP TABLE foo")
    end

    test "ALTER TABLE is unsafe" do
      refute @subject.read_safe?("ALTER TABLE foo ADD COLUMN bar text")
    end

    test "CREATE INDEX is unsafe" do
      refute @subject.read_safe?("CREATE INDEX ON foo (id)")
    end

    test "GRANT is unsafe" do
      refute @subject.read_safe?("GRANT SELECT ON users TO bob")
    end
  end

  describe "read_safe?/1 - transaction statements" do
    test "BEGIN READ ONLY" do
      assert @subject.read_safe?("BEGIN READ ONLY")
    end

    test "BEGIN TRANSACTION READ ONLY" do
      assert @subject.read_safe?("BEGIN TRANSACTION READ ONLY")
    end

    test "START TRANSACTION READ ONLY" do
      assert @subject.read_safe?("START TRANSACTION READ ONLY")
    end

    test "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY" do
      assert @subject.read_safe?("BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY")
    end

    test "BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ" do
      assert @subject.read_safe?("BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ")
    end

    # Everything else is unsafe:

    test "BEGIN is unsafe" do
      refute @subject.read_safe?("BEGIN")
    end

    test "BEGIN READ WRITE is unsafe" do
      refute @subject.read_safe?("BEGIN READ WRITE")
    end

    test "BEGIN ISOLATION LEVEL SERIALIZABLE alone is unsafe (no READ ONLY)" do
      refute @subject.read_safe?("BEGIN ISOLATION LEVEL SERIALIZABLE")
    end

    test "COMMIT is unsafe" do
      refute @subject.read_safe?("COMMIT")
    end

    test "ROLLBACK is unsafe" do
      refute @subject.read_safe?("ROLLBACK")
    end

    test "SAVEPOINT is unsafe" do
      refute @subject.read_safe?("SAVEPOINT s1")
    end
  end

  describe "read_safe?/1 - unsafe select statements" do
    # SELECT ... INTO creates a table:

    test "SELECT INTO new_table" do
      refute @subject.read_safe?("SELECT * INTO new_table FROM users")
    end

    test "SELECT INTO TEMP table" do
      refute @subject.read_safe?("SELECT * INTO TEMP scratch FROM users")
    end

    test "SELECT INTO inside a CTE" do
      refute @subject.read_safe?("""
             WITH x AS (SELECT * INTO new_table FROM users)
             SELECT * FROM x
             """)
    end

    # Locking clauses acquire row locks:

    test "SELECT ... FOR UPDATE" do
      refute @subject.read_safe?("SELECT * FROM users FOR UPDATE")
    end

    test "SELECT ... FOR SHARE" do
      refute @subject.read_safe?("SELECT * FROM users FOR SHARE")
    end

    test "SELECT ... FOR NO KEY UPDATE" do
      refute @subject.read_safe?("SELECT * FROM users FOR NO KEY UPDATE")
    end

    test "SELECT ... FOR KEY SHARE" do
      refute @subject.read_safe?("SELECT * FROM users FOR KEY SHARE")
    end

    test "SELECT ... FOR UPDATE OF specific table" do
      refute @subject.read_safe?("SELECT * FROM users u WHERE u.id = 1 FOR UPDATE OF u")
    end

    test "FOR UPDATE inside a CTE" do
      refute @subject.read_safe?("""
             WITH locked AS (SELECT * FROM users FOR UPDATE)
             SELECT * FROM locked
             """)
    end

    test "FOR UPDATE inside a sub-SELECT in FROM" do
      refute @subject.read_safe?("""
             SELECT * FROM (SELECT * FROM users FOR UPDATE) sub
             """)
    end

    # CTE wrapping a write:

    test "CTE wrapping INSERT" do
      refute @subject.read_safe?("""
             WITH x AS (INSERT INTO log VALUES (1) RETURNING *)
             SELECT * FROM x
             """)
    end

    test "CTE wrapping UPDATE" do
      refute @subject.read_safe?("""
             WITH x AS (UPDATE users SET name = 'x' RETURNING *)
             SELECT * FROM x
             """)
    end

    test "CTE wrapping DELETE" do
      refute @subject.read_safe?("""
             WITH x AS (DELETE FROM log RETURNING *)
             SELECT * FROM x
             """)
    end

    test "nested CTE where inner body is a write" do
      refute @subject.read_safe?("""
             WITH wrapper AS (
               WITH body AS (INSERT INTO log VALUES (1) RETURNING *)
               SELECT * FROM body
             )
             SELECT * FROM wrapper
             """)
    end

    test "multiple CTEs where any one is a write" do
      refute @subject.read_safe?("""
             WITH a AS (SELECT 1),
                  b AS (DELETE FROM log RETURNING *),
                  c AS (SELECT 2)
             SELECT * FROM a, b, c
             """)
    end

    # Any function call:

    test "built-in function" do
      refute @subject.read_safe?("SELECT count(*) FROM users")
    end

    test "user-defined function" do
      refute @subject.read_safe?("SELECT my_custom_function(1, 'x')")
    end

    test "function call in WHERE clause" do
      refute @subject.read_safe?("SELECT * FROM users WHERE length(name) > 5")
    end

    test "function call in JOIN ON clause" do
      refute @subject.read_safe?("SELECT * FROM a JOIN b ON a.id = pg_advisory_lock(b.id)")
    end

    test "function call inside CTE body" do
      refute @subject.read_safe?("""
             WITH counts AS (SELECT count(*) AS n FROM users)
             SELECT * FROM counts
             """)
    end

    test "function call inside sub-SELECT in FROM" do
      refute @subject.read_safe?("SELECT * FROM (SELECT lower(email) AS e FROM users) sub")
    end

    test "function nested inside COALESCE" do
      refute @subject.read_safe?("SELECT COALESCE(nextval('s'), 0)")
    end

    test "function nested inside CASE" do
      refute @subject.read_safe?("""
             SELECT CASE WHEN true THEN nextval('s') ELSE 0 END
             """)
    end

    test "function nested inside TypeCast" do
      refute @subject.read_safe?("SELECT nextval('s')::bigint")
    end
  end

  describe "read_safe?/1 - multi-statement queries" do
    test "two pure SELECTs is safe" do
      assert @subject.read_safe?("SELECT 1; SELECT 2")
    end

    test "SELECT followed by UPDATE is unsafe" do
      refute @subject.read_safe?("SELECT 1; UPDATE x SET y = 1")
    end

    test "two writes is unsafe" do
      refute @subject.read_safe?("INSERT INTO x VALUES (1); INSERT INTO x VALUES (2)")
    end
  end

  describe "read_safe?/1 - parse errors return false" do
    test "empty string" do
      refute @subject.read_safe?("")
    end

    test "whitespace only" do
      refute @subject.read_safe?("   \n\t  ")
    end

    test "comment only" do
      refute @subject.read_safe?("-- just a comment")
    end

    test "garbage SQL" do
      refute @subject.read_safe?("not valid sql at all")
    end

    test "incomplete SQL" do
      refute @subject.read_safe?("SELECT * FROM")
    end
  end
end
