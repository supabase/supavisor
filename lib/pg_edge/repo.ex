defmodule PgEdge.Repo do
  use Ecto.Repo,
    otp_app: :pg_edge,
    adapter: Ecto.Adapters.Postgres
end
