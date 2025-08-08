defmodule Supavisor.MD5Repo do
  use Ecto.Repo,
    otp_app: :supavisor,
    adapter: Ecto.Adapters.Postgres
end
