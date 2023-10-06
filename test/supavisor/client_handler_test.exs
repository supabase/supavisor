defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler

  describe "parse_user_info/1" do
    test "extracts the external_id from the username" do
      payload = %{"user" => "test.user.external_id"}
      {name, external_id} = ClientHandler.parse_user_info(payload)
      assert name == "test.user"
      assert external_id == "external_id"
    end

    test "username consists only of username" do
      username = "username"
      payload = %{"user" => username}
      {user, nil} = ClientHandler.parse_user_info(payload)
      assert username == user
    end

    test "external_id in options" do
      user = "test.user"
      external_id = "external_id"
      payload = %{"options" => %{"reference" => external_id}, "user" => user}
      {user1, external_id1} = ClientHandler.parse_user_info(payload)
      assert user1 == user
      assert external_id1 == external_id
    end
  end
end
