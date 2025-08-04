alias Supavisor.Tenants
alias Supavisor.Repo
import Ecto.Adapters.SQL, only: [query: 3]

auth_profiles_conf = Application.get_env(:supavisor, :test_auth_profiles)

tenant_name = "dev_tenant"

if Tenants.get_tenant_by_external_id(tenant_name) do
  Tenants.delete_tenant_by_external_id(tenant_name)
end

auth_profiles_conf
|> Enum.each(fn {key, {db_conf, _repo}} ->
  if !Tenants.get_tenant_by_external_id("is_manager_#{key}") do
    {:ok, _} =
      %{
        db_host: db_conf[:hostname],
        db_port: db_conf[:port],
        db_database: db_conf[:database],
        default_parameter_status: %{},
        external_id: "is_manager_#{key}",
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
end)

["proxy_tenant1", "syn_tenant", "prom_tenant", "max_pool_tenant", "metrics_tenant"]
|> Enum.each(fn tenant ->
  if !Tenants.get_tenant_by_external_id(tenant) do
    {db_conf, _repo} = auth_profiles_conf[:"scram-sha-256"]

    {:ok, _} =
      %{
        db_host: db_conf[:hostname],
        db_port: db_conf[:port],
        db_database: db_conf[:database],
        default_parameter_status: %{},
        external_id: tenant,
        require_user: true,
        users: [
          %{
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 9,
            "max_clients" => 100,
            "mode_type" => "transaction"
          },
          %{
            "db_user_alias" => "transaction",
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 3,
            "max_clients" => 100,
            "mode_type" => "transaction"
          },
          %{
            "db_user_alias" => "session",
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 1,
            "mode_type" => "session",
            "max_clients" => 100,
            "pool_checkout_timeout" => 500
          },
          %{
            "db_user_alias" => "max_clients",
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 1,
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
