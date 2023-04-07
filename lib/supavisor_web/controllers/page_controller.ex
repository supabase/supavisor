defmodule SupavisorWeb.PageController do
  use SupavisorWeb, :controller

  def index(conn, _params) do
    redirect(conn, to: "/swaggerui")
  end
end
