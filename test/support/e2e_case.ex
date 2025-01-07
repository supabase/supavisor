defmodule Supavisor.E2ECase do
  use ExUnit.CaseTemplate

  @repo Supavisor.Repo

  using do
    quote do
      alias unquote(@repo)

      import unquote(__MODULE__)
    end
  end

  setup tags do
    if tags[:async] do
      raise "End to end tests must be run in synchronous mode"
    end

    Supavisor.DataCase.setup_sandbox(tags)
  end

  def unboxed(fun) do
    Ecto.Adapters.SQL.Sandbox.unboxed_run(@repo, fun)
  end

  def create_instance(external_id) do
    external_id =
      external_id
      |> List.wrap()
      |> Enum.map_join("_", &String.replace(to_string(&1), ~r/\W/, "_"))
      |> String.downcase()

    unboxed(fn ->
      assert {:ok, _} = @repo.query("DROP DATABASE IF EXISTS #{external_id}")
      assert {:ok, _} = @repo.query("CREATE DATABASE #{external_id}")
    end)

    assert {:ok, tenant} =
             Supavisor.Tenants.create_tenant(%{
               default_parameter_status: %{},
               db_host: "localhost",
               db_port: 6432,
               db_database: external_id,
               auth_query: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1;",
               external_id: external_id,
               users: [
                 %{
                   "pool_size" => 15,
                   "db_user" => "postgres",
                   "db_password" => "postgres",
                   "is_manager" => true,
                   "mode_type" => "session"
                 }
               ]
             })

    on_exit(fn ->
      :ok = Supavisor.stop({{:single, external_id}, "postgres", :session, external_id, nil})

      unboxed(fn ->
        assert {:ok, _} = @repo.query("DROP DATABASE #{external_id}")
      end)
    end)

    {:ok, %{user: "postgres.#{external_id}", db: tenant.db_database, external_id: external_id}}
  end
end
