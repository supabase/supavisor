defmodule SupavisorWeb.PageController do
  use SupavisorWeb, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
