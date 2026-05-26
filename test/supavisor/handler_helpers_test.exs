defmodule Supavisor.HandlerHelpersTest do
  use ExUnit.Case, async: true

  @subject Supavisor.HandlerHelpers

  doctest @subject

  describe "sock_send/2 with :proc variant" do
    test "delivers bytes to the target pid as {:db_bytes, binary}" do
      :ok = @subject.sock_send({:proc, self()}, "hello")
      assert_received {:db_bytes, "hello"}
    end

    test "flattens iodata into a single binary" do
      :ok = @subject.sock_send({:proc, self()}, ["foo", [?b, "ar"], "baz"])
      assert_received {:db_bytes, "foobarbaz"}
    end

    test "accepts empty iodata" do
      :ok = @subject.sock_send({:proc, self()}, [])
      assert_received {:db_bytes, ""}
    end
  end

  describe "setopts/2 and sock_close/1 with :proc variant" do
    test "setopts is a no-op" do
      assert :ok = @subject.setopts({:proc, self()}, active: :once)
    end

    test "sock_close is a no-op" do
      assert :ok = @subject.sock_close({:proc, self()})
    end
  end

  describe "parse_user_info/1" do
    test "extracts the external_id from the username" do
      payload = %{"user" => "test.user.external_id"}
      {:single, {name, external_id, nil}} = @subject.parse_user_info(payload)
      assert name == "test.user"
      assert external_id == "external_id"
    end

    test "username consists only of username" do
      username = "username"
      payload = %{"user" => username}
      {:single, {user, nil, nil}} = @subject.parse_user_info(payload)
      assert username == user
    end

    test "consist cluster" do
      username = "some.user.cluster.alias"
      {t, {u, a, nil}} = @subject.parse_user_info(%{"user" => username})
      assert {t, {u, a, nil}} == {:cluster, {"some.user", "alias", nil}}
    end

    test "external_id in options" do
      user = "test.user"
      external_id = "external_id"
      payload = %{"options" => %{"reference" => external_id}, "user" => user}
      {:single, {user1, external_id1, nil}} = @subject.parse_user_info(payload)
      assert user1 == user
      assert external_id1 == external_id
    end

    test "unicode in username" do
      payload = %{"user" => "тестовe.імʼя.external_id"}
      {:single, {name, external_id, nil}} = @subject.parse_user_info(payload)
      assert name == "тестовe.імʼя"
      assert external_id == "external_id"
    end

    test "extracts db_name" do
      payload = %{"user" => "user", "database" => "postgres_test"}
      {:single, {name, nil, db_name}} = @subject.parse_user_info(payload)
      assert name == "user"
      assert db_name == "postgres_test"
    end
  end
end
