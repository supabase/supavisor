defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler

  describe "parse_user_info/1" do
    test "extracts the external_id from the username" do
      username = "test.user.external_id"
      {:single, {name, external_id}} = ClientHandler.parse_user_info(username)
      assert name == "test.user"
      assert external_id == "external_id"
    end

    test "username consists only of username" do
      username = "username"
      {:single, {user, nil}} = ClientHandler.parse_user_info(username)
      assert username == user
    end

    test "consist cluster" do
      username = "username"
      {t, {u, a}} = ClientHandler.parse_user_info(username)
      assert {t, {u, a}} == {:cluster, {"some.user", "alias"}}
    end
  end
end
