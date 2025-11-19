defmodule Supavisor.ClientHandler.HTTP do
  @moduledoc false

  alias Supavisor.HandlerHelpers
  require Logger

  def handle_http_request(data) do
    Logger.debug("ClientHandler: Client is trying to request HTTP")

    HandlerHelpers.sock_send(
      data.sock,
      "HTTP/1.1 204 OK\r\nx-app-version: #{Application.spec(:supavisor, :vsn)}\r\n\r\n"
    )

    {:stop, :normal}
  end
end
