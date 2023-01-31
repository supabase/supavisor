import Ecto.Adapters.SQL, only: [query: 3]

[
  "create schema if not exists pgedge"
] |> Enum.each(&query(PgEdge.Repo, &1, []))
