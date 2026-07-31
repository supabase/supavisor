defmodule Supavisor.ParseShapeCorpus do
  @moduledoc """
  SQL corpus: differential test data for the shape cache.

  - `same_shape_groups/0`: SQLs within a group differ lexically but share a
    shape (constant value changes, whitespace/comment/case variants); they
    must produce identical results and, after warm-up, must hit the same
    cache entry.
  - `distinct_shape_pairs/0`: two SQLs with different shapes; the first call
    of each must be a miss (neither may hit the other's entry).
  """

  @doc "Returns [[sql, ...], ...]; all SQLs in a group share a shape and a result"
  def same_shape_groups do
    [
      [
        "SELECT * FROM corpus_sel WHERE id = 1",
        "SELECT * FROM corpus_sel WHERE id = 999",
        "  select  *  from   corpus_sel\nwhere id = -42 -- trailing\n",
        "SELECT /* c */ * FROM corpus_sel WHERE id = 3;",
        "SELECT * FROM corpus_sel WHERE \"id\" = 5"
      ],
      [
        "INSERT INTO corpus_ins (a, b) VALUES (1, 'x')",
        "INSERT INTO corpus_ins (a, b) VALUES (2, 'y')",
        "insert into corpus_ins (a, b) values (3, 'z');"
      ],
      [
        "UPDATE corpus_upd SET a = 1 WHERE id = 1",
        "UPDATE corpus_upd SET a = 2 WHERE id = 2"
      ],
      [
        "DELETE FROM corpus_del WHERE id = 1",
        "DELETE FROM corpus_del WHERE id = 2"
      ],
      [
        "SELECT * FROM corpus_par WHERE id = $1",
        "SELECT * FROM corpus_par WHERE id = $1;"
      ],
      [
        "SELECT * FROM corpus_str WHERE note = '-- ; /* */'",
        "SELECT * FROM corpus_str WHERE note = '完全不同的内容'"
      ]
    ]
  end

  @doc "Returns [{sql_a, sql_b}, ...]; the two SQLs have different shapes"
  def distinct_shape_pairs do
    [
      {"SELECT * FROM corpus_d1 WHERE id = 1", "SELECT * FROM corpus_d1 WHERE id = 'a'"},
      {"SELECT * FROM corpus_d2 WHERE id = $1", "SELECT * FROM corpus_d2 WHERE id = $2"},
      {"SELECT * FROM corpus_d3 WHERE id = 1", "SELECT * FROM corpus_d4 WHERE id = 1"},
      {"SELECT * FROM corpus_d5 WHERE \"id\" = 1", "SELECT * FROM corpus_d5 WHERE \"ID\" = 1"},
      {"SELECT id FROM corpus_d6", "SELECT name FROM corpus_d6"},
      {"INSERT INTO corpus_d7 (a) VALUES (1)", "UPDATE corpus_d7 SET a = 1"}
    ]
  end
end
