defmodule SupavisorTest do
  use ExUnit.Case, async: true

  require Supavisor

  describe "inspect_id/1" do
    test "key and value are never split across lines" do
      id =
        Supavisor.id(
          type: :single,
          tenant: "some_very_long_tenant_name_that_could_cause_wrapping",
          user: "postgres",
          mode: :session,
          db: "some_very_long_tenant_name_that_could_cause_wrapping",
          search_path: nil
        )

      assert Supavisor.inspect_id(id) == """
             Supavisor.id(
               type: :single,
               tenant: "some_very_long_tenant_name_that_could_cause_wrapping",
               mode: :session,
               user: "postgres",
               db: "some_very_long_tenant_name_that_could_cause_wrapping"
             )\
             """
    end

    test "omits nil values" do
      id =
        Supavisor.id(
          type: :single,
          tenant: "my_tenant",
          user: "postgres",
          mode: :session,
          db: "my_db",
          search_path: nil
        )

      assert Supavisor.inspect_id(id) == """
             Supavisor.id(type: :single, tenant: "my_tenant", mode: :session, user: "postgres", db: "my_db")\
             """
    end

    test "includes search_path when set" do
      id =
        Supavisor.id(
          type: :single,
          tenant: "my_tenant",
          user: "postgres",
          mode: :session,
          db: "my_db",
          search_path: "public"
        )

      assert Supavisor.inspect_id(id) ==
               """
               Supavisor.id(type: :single, tenant: "my_tenant", mode: :session, user: "postgres", db: "my_db", search_path: "public")\
               """
    end

    test "falls back to inspect for invalid ids" do
      assert Supavisor.inspect_id(:not_an_id) == ":not_an_id"
    end
  end
end
