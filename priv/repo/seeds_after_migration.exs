alias Supavisor.Tenants
alias Supavisor.Repo
import Ecto.Adapters.SQL, only: [query: 3]

db_conf = Application.get_env(:supavisor, Repo)

tenant_name = "dev_tenant"
proxy_tenant = "proxy_tenant"

if Tenants.get_tenant_by_external_id(tenant_name) do
  Tenants.delete_tenant_by_external_id(tenant_name)
end

if !Tenants.get_tenant_by_external_id(proxy_tenant) do
  %{
    db_database: db_conf[:database],
    db_host: db_conf[:hostname],
    db_password: db_conf[:password],
    db_port: db_conf[:port],
    db_user: db_conf[:username],
    external_id: proxy_tenant,
    pool_size: 3
  } |> Tenants.create_tenant()
end

{:ok, _} =
  Repo.transaction(fn ->
    [
      "drop table if exists \"public\".\"test\";",
      "create sequence if not exists test_id_seq;",
      "create table \"public\".\"test\" (
        \"id\" int4 not null default nextval('test_id_seq'::regclass),
        \"details\" text,
        primary key (\"id\")
    );",
      "grant all on table public.test to anon;",
      "grant all on table public.test to postgres;",
      "grant all on table public.test to authenticated;"
    ]
    |> Enum.each(&query(Repo, &1, []))
  end)
