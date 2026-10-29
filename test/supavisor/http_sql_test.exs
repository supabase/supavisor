defmodule Supavisor.HttpSqlTest do
  use ExUnit.Case, async: true

  alias Supavisor.HttpSql

  @conn_string "postgresql://postgres.tenant:postgres@localhost/postgres"
  @client %{ip: "127.0.0.1", tls: false}

  test "rejects a missing or invalid connection string" do
    for conn_string <- [nil, "postgres://user@host/db", "postgres://user:pass@host", "nope"] do
      assert {:error, {:bad_request, _}} =
               HttpSql.run(conn_string, %{"query" => "SELECT 1"}, %{}, @client)
    end
  end

  test "rejects a body without a query" do
    for body <- [%{}, %{"query" => 1}, %{"queries" => [%{}]}, %{"queries" => "SELECT 1"}] do
      assert {:error, {:bad_request, _}} = HttpSql.run(@conn_string, body, %{}, @client)
    end
  end

  test "rejects params that aren't scalars" do
    for params <- [[[1, 2]], [%{"a" => 1}], "1"] do
      assert {:error, {:bad_request, _}} =
               HttpSql.run(
                 @conn_string,
                 %{"query" => "SELECT $1", "params" => params},
                 %{},
                 @client
               )
    end
  end

  test "rejects an unknown isolation level" do
    headers = %{"neon-batch-isolation-level" => "Serializable; DROP TABLE users"}

    assert {:error, {:bad_request, _}} =
             HttpSql.run(
               @conn_string,
               %{"queries" => [%{"query" => "SELECT 1"}]},
               headers,
               @client
             )
  end
end
