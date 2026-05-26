defmodule Supavisor.ReadSafe do
  @moduledoc """
  Read-only classifier for SQL queries.

  This stays conservative and does not try to guess anything outside of the query AST. As a result
  it might miss out on possible read-safe queries that couldn't be judged purely by their AST.
  """

  alias Supavisor.PgParser

  @doc """
  Returns `true` if the SQL query is guaranteed to be read-only.
  """
  @spec read_safe?(String.t()) :: boolean()
  def read_safe?(sql) do
    case PgParser.parse(sql) do
      {:ok, %{"stmts" => stmts}} when is_list(stmts) and stmts != [] ->
        all_safe?(stmts)

      _ ->
        false
    end
  end

  # All statements in the query must be read-only.
  defp all_safe?(stmts), do: Enum.all?(stmts, &safe_stmt?/1)

  # We only care about `SELECT` and transactional (`BEGIN` or `START TRANSACTION`) statements.
  defp safe_stmt?(%{"stmt" => %{"SelectStmt" => select}}), do: safe_select?(select)
  defp safe_stmt?(%{"stmt" => %{"TransactionStmt" => txn}}), do: safe_transaction?(txn)
  defp safe_stmt?(_), do: false

  # Check for `BEGIN READ ONLY` or `START TRANSACTION READ ONLY` statements.
  defp safe_transaction?(%{"kind" => kind, "options" => opts})
       when kind in ["TRANS_STMT_BEGIN", "TRANS_STMT_START"] and is_list(opts) do
    Enum.any?(opts, fn
      %{
        "DefElem" => %{
          "defname" => "transaction_read_only",
          "arg" => %{"A_Const" => %{"ival" => %{"ival" => 1}}}
        }
      } ->
        true

      _ ->
        false
    end)
  end

  defp safe_transaction?(_), do: false

  # A `SELECT` statement can still write, check for all cases.
  defp safe_select?(select) do
    not walk(select, fn pair ->
      into_clause?(pair) or locking_clause?(pair) or cte_write?(pair) or func_call?(pair)
    end)
  end

  # `SELECT ... INTO new_table` creates a table.
  defp into_clause?({"intoClause", clause}) when not is_nil(clause), do: true
  defp into_clause?(_), do: false

  # `SELECT ... FOR UPDATE | FOR SHARE | FOR NO KEY UPDATE | FOR KEY SHARE` acquires row locks.
  defp locking_clause?({"lockingClause", clauses}) when is_list(clauses) and clauses != [],
    do: true

  defp locking_clause?(_), do: false

  # A `WITH x AS (INSERT/UPDATE/DELETE ...) SELECT ...` CTE hides a write inside an outer SELECT.
  defp cte_write?({"CommonTableExpr", %{"ctequery" => %{"SelectStmt" => _}}}), do: false
  defp cte_write?({"CommonTableExpr", %{"ctequery" => _other}}), do: true
  defp cte_write?(_), do: false

  # Any function call is treated as potentially write-effecting, as there is no way
  # to definitely tell if a function is read-only without asking the DB.
  defp func_call?({"FuncCall", _}), do: true
  defp func_call?(_), do: false

  # Query tree walker that stops when the predicate is true.
  defp walk(value, pred) when is_map(value) do
    Enum.any?(value, fn {_k, v} = pair ->
      pred.(pair) or walk(v, pred)
    end)
  end

  defp walk(value, pred) when is_list(value), do: Enum.any?(value, &walk(&1, pred))
  defp walk(_value, _pred), do: false
end
