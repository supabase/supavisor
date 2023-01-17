defmodule PgEdgeWeb.PageController do
  use PgEdgeWeb, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
