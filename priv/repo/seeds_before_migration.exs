import Ecto.Adapters.SQL, only: [query: 3]

[
  "create schema if not exists _supavisor",
  "create role anon          nologin noinherit;",
  "create role authenticated nologin noinherit;",
  "create role service_role  nologin noinherit bypassrls;",
]
|> Enum.each(&query(Supavisor.Repo, &1, []))
