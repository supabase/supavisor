defmodule Supavisor.Helpers do
  @moduledoc false

  @type user_info :: %{
          "db_password" => String.t(),
          "db_user" => String.t(),
          "db_user_alias" => String.t(),
          "mode_type" => String.t(),
          "pool_checkout_timeout" => integer(),
          "pool_size" => integer()
        }

  @type creds_params :: %{
          "db_database" => String.t(),
          "db_host" => String.t(),
          "db_port" => integer(),
          "users" => [user_info]
        }

  @spec check_creds_get_ver(creds_params) :: {:ok, String.t()} | {:error, String.t()}
  def check_creds_get_ver(params) do
    Enum.reduce_while(params["users"], {nil, nil}, fn user, _ ->
      {:ok, conn} =
        Postgrex.start_link(
          hostname: params["db_host"],
          port: params["db_port"],
          database: params["db_database"],
          password: user["db_password"],
          username: user["db_user"]
        )

      check =
        Postgrex.query(conn, "select version()", [])
        |> case do
          {:ok, %{rows: [[version]]}} = r ->
            {:cont, {:ok, version}}

          _ ->
            {:halt, {:error, "Invalid credentials for user #{user["db_user"]}"}}
        end

      GenServer.stop(conn)
      check
    end)
    |> case do
      {:ok, version} ->
        case Regex.run(~r/PostgreSQL\s(\d*.\d*)/, version) do
          nil ->
            {:error, "Can't parse version in #{version}"}

          [_, value] ->
            {:ok, value}
        end

      other ->
        other
    end
  end
end
