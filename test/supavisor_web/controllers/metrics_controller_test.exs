defmodule SupavisorWeb.MetricsControllerTest do
  use SupavisorWeb.ConnCase

  setup %{conn: conn} do
    new_conn =
      conn
      |> put_req_header(
        "authorization",
        "Bearer auth_token"
      )

    {:ok, conn: new_conn}
  end

  test "exporting metrics", %{conn: conn} do
    :meck.expect(Supavisor.Jwt, :authorize, fn _token, _secret -> {:ok, %{}} end)
    conn = get(conn, Routes.metrics_path(conn, :index))
    assert conn.status == 200
    assert conn.resp_body =~ "region=\"eu\""
    assert conn.resp_body =~ "region=\"usa\""
  end

  test "invalid jwt", %{conn: conn} do
    :meck.expect(Supavisor.Jwt, :authorize, fn _token, _secret -> {:error, nil} end)
    conn = get(conn, Routes.metrics_path(conn, :index))
    assert conn.status == 403
  end
end
