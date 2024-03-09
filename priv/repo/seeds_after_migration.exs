alias Supavisor.Tenants
alias Supavisor.Repo
import Ecto.Adapters.SQL, only: [query: 3]

db_conf = Application.get_env(:supavisor, Repo)

tenant_name = "dev_tenant"

if Tenants.get_tenant_by_external_id(tenant_name) do
  Tenants.delete_tenant_by_external_id(tenant_name)
end

{:ok, version} =
  case Repo.query!("select version()") do
    %{rows: [[ver]]} -> Supavisor.Helpers.parse_pg_version(ver)
    _ -> nil
  end

if !Tenants.get_tenant_by_external_id("is_manager") do
  %{
    db_host: db_conf[:hostname],
    db_port: db_conf[:port],
    db_database: db_conf[:database],
    external_id: "is_manager",
    default_parameter_status: %{server_version: version},
    require_user: false,
    auth_query: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1;",
    users: [
      %{
        "db_user" => db_conf[:username],
        "db_password" => db_conf[:password],
        "pool_size" => 2,
        "mode_type" => "transaction",
        "is_manager" => true,
        "pool_checkout_timeout" => 1000
      }
    ]
  }
  |> Tenants.create_tenant()
end

["proxy_tenant1", "syn_tenant", "prom_tenant"]
|> Enum.each(fn tenant ->
  if !Tenants.get_tenant_by_external_id(tenant) do
    %{
      db_host: db_conf[:hostname],
      db_port: db_conf[:port],
      db_database: db_conf[:database],
      external_id: tenant,
      default_parameter_status: %{server_version: version},
      require_user: true,
      users: [
        %{
          "db_user" => db_conf[:username],
          "db_password" => db_conf[:password],
          "pool_size" => 9,
          "mode_type" => "transaction"
        },
        %{
          "db_user_alias" => "transaction",
          "db_user" => db_conf[:username],
          "db_password" => db_conf[:password],
          "pool_size" => 3,
          "mode_type" => "transaction"
        },
        %{
          "db_user_alias" => "session",
          "db_user" => db_conf[:username],
          "db_password" => db_conf[:password],
          "pool_size" => 1,
          "mode_type" => "session",
          "pool_checkout_timeout" => 500
        },
        %{
          "db_user_alias" => "max_clients",
          "db_user" => db_conf[:username],
          "db_password" => db_conf[:password],
          "pool_size" => 2,
          "max_clients" => -1,
          "mode_type" => "transaction",
          "pool_checkout_timeout" => 500
        }
      ]
    }
    |> Tenants.create_tenant()
  end
end)

{:ok, _} =
  Repo.transaction(fn ->
    [
      "drop user if exists dev_postgres;",
      "create user dev_postgres with password 'postgres';",
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
