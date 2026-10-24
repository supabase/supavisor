defmodule SupavisorWeb.HttpSql do
  @moduledoc """
  The `/sql` endpoint, serving `Supavisor.HttpSql` to Neon's serverless driver.
  """

  @behaviour Plug

  require Logger

  import Plug.Conn

  alias Supavisor.HttpSql

  @allowed_headers "Authorization, Neon-Connection-String, Neon-Raw-Text-Output, Neon-Array-Mode, " <>
                     "Neon-Batch-Isolation-Level, Neon-Batch-Read-Only, Neon-Batch-Deferrable"

  @impl true
  def init(opts), do: opts

  @impl true
  def call(%Plug.Conn{method: "OPTIONS"} = conn, _opts) do
    conn
    |> put_resp_header("access-control-allow-origin", "*")
    |> put_resp_header("allow", "OPTIONS, POST")
    |> put_resp_header("access-control-allow-headers", @allowed_headers)
    |> put_resp_header("access-control-max-age", "86400")
    |> send_resp(200, "")
  end

  def call(conn, _opts) do
    conn = put_resp_header(conn, "access-control-allow-origin", "*")
    conn_string = conn |> get_req_header("neon-connection-string") |> List.first()
    client = %{ip: conn.remote_ip |> :inet.ntoa() |> to_string(), tls: conn.scheme == :https}

    with :ok <- reject_jwt(conn),
         {:ok, body, conn} <- read_json_body(conn),
         {:ok, response} <-
           HttpSql.run(conn_string, body, Map.new(conn.req_headers), client) do
      send(conn, 200, response)
    else
      # Returning 400 for both Postgres errors and bad requests is consistent with
      # Neon's own server behavior. The driver shows the error details for 400s only.
      {:error, {:postgres, error}} ->
        send(conn, 400, error)

      {:error, {:bad_request, message}} ->
        send(conn, 400, json(message))

      {:error, :body_too_large} ->
        send(conn, 413, json("request body too large"))

      {:error, {:response_too_large, max}} ->
        send(conn, 507, json("response is too large (max is #{max} bytes)"))

      {:error, reason} ->
        Logger.error("HttpSql: request failed: #{inspect(reason)}")
        send(conn, 500, json("internal error"))
    end
  end

  defp reject_jwt(conn) do
    case get_req_header(conn, "authorization") do
      [] -> :ok
      _ -> {:error, {:bad_request, "JWT authentication is not supported"}}
    end
  end

  # The driver doesn't set a content type, so its body isn't parsed before it gets here.
  defp read_json_body(%Plug.Conn{body_params: %Plug.Conn.Unfetched{}} = conn) do
    with {:ok, body, conn} <- read_body(conn),
         {:ok, %{} = body} <- JSON.decode(body) do
      {:ok, body, conn}
    else
      {:more, _partial, _conn} -> {:error, :body_too_large}
      _ -> {:error, {:bad_request, "invalid request body"}}
    end
  end

  defp read_json_body(conn), do: {:ok, conn.body_params, conn}

  defp json(message), do: JSON.encode_to_iodata!(%{"message" => message})

  defp send(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, body)
  end
end
