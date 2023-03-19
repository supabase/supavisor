defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler

  describe "get_external_id/1" do
    test "extracts the external_id from the username" do
      username = "test.user.external_id"
      external_id = ClientHandler.get_external_id(username)
      assert external_id == "external_id"
    end
  end
end
