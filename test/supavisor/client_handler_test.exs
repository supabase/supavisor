defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.HandlerHelpers, as: HH

  describe "parse_user_info/1" do
    test "extracts the external_id from the username" do
      payload = %{"user" => "test.user.external_id"}
      {:single, {name, external_id, nil}} = HH.parse_user_info(payload)
      assert name == "test.user"
      assert external_id == "external_id"
    end

    test "username consists only of username" do
      username = "username"
      payload = %{"user" => username}
      {:single, {user, nil, nil}} = HH.parse_user_info(payload)
      assert username == user
    end

    test "consist cluster" do
      username = "some.user.cluster.alias"
      {t, {u, a, nil}} = HH.parse_user_info(%{"user" => username})
      assert {t, {u, a, nil}} == {:cluster, {"some.user", "alias", nil}}
    end

    test "external_id in options" do
      user = "test.user"
      external_id = "external_id"
      payload = %{"options" => %{"reference" => external_id}, "user" => user}
      {:single, {user1, external_id1, nil}} = HH.parse_user_info(payload)
      assert user1 == user
      assert external_id1 == external_id
    end

    test "unicode in username" do
      payload = %{"user" => "тестовe.імʼя.external_id"}
      {:single, {name, external_id, nil}} = HH.parse_user_info(payload)
      assert name == "тестовe.імʼя"
      assert external_id == "external_id"
    end

    test "extracts db_name" do
      payload = %{"user" => "user", "database" => "postgres_test"}
      {:single, {name, nil, db_name}} = HH.parse_user_info(payload)
      assert name == "user"
      assert db_name == "postgres_test"
    end
  end
end
