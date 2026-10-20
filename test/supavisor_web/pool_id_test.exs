defmodule SupavisorWeb.PoolIdTest do
  use ExUnit.Case, async: true

  require Supavisor

  alias SupavisorWeb.PoolId

  defp id(opts \\ []) do
    Supavisor.id(
      type: opts[:type] || :single,
      tenant: opts[:tenant] || "t1",
      user: opts[:user] || "postgres",
      mode: opts[:mode] || :transaction,
      db: opts[:db] || "postgres",
      search_path: Keyword.get(opts, :search_path),
      upstream_tls: Keyword.get(opts, :upstream_tls, false)
    )
  end

  defp token(overrides) do
    %{
      "type" => "single",
      "tenant" => "t1",
      "user" => "postgres",
      "mode" => "transaction",
      "database" => "postgres"
    }
    |> Map.merge(overrides)
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  describe "id_to_map/1" do
    test "serializes a pool id to its external map" do
      assert PoolId.id_to_map(id(search_path: "public", upstream_tls: true)) == %{
               type: :single,
               tenant: "t1",
               user: "postgres",
               mode: :transaction,
               database: "postgres",
               search_path: "public",
               upstream_tls: true
             }
    end
  end

  describe "encode_token/1 <-> decode_token/1" do
    test "round-trips a single pool id" do
      i = id()
      assert {:ok, ^i} = i |> PoolId.encode_token() |> PoolId.decode_token()
    end

    test "round-trips with search_path and upstream_tls set" do
      i = id(mode: :session, search_path: "public,extensions", upstream_tls: true)
      assert {:ok, ^i} = i |> PoolId.encode_token() |> PoolId.decode_token()
    end

    test "round-trips a cluster id" do
      i = id(type: :cluster, mode: :session, db: "other")
      assert {:ok, ^i} = i |> PoolId.encode_token() |> PoolId.decode_token()
    end

    test "produces a URL-safe, unpadded token" do
      assert PoolId.encode_token(id()) =~ ~r/^[A-Za-z0-9_-]+$/
    end

    test "rejects malformed tokens" do
      assert {:error, :invalid_token} = PoolId.decode_token("not base64 !!")
      assert {:error, :invalid_token} = PoolId.decode_token(Base.url_encode64("not json"))
      assert {:error, :invalid_token} = PoolId.decode_token(123)
    end
  end

  describe "decode_token/1 validation" do
    test "builds an id from a valid token" do
      assert {:ok, i} = PoolId.decode_token(token(%{}))
      assert i == id()
    end

    test "casts enum strings to atoms" do
      assert {:ok, i} = PoolId.decode_token(token(%{"type" => "cluster", "mode" => "session"}))
      assert Supavisor.id(i, :type) == :cluster
      assert Supavisor.id(i, :mode) == :session
    end

    test "defaults upstream_tls to false and search_path to nil" do
      assert {:ok, i} = PoolId.decode_token(token(%{}))
      assert Supavisor.id(i, :upstream_tls) == false
      assert Supavisor.id(i, :search_path) == nil
    end

    test "rejects modes a pool cannot have" do
      for mode <- ["nope", "proxy", "native"] do
        assert {:error, :invalid_token} = PoolId.decode_token(token(%{"mode" => mode}))
      end
    end

    test "requires the mandatory fields" do
      for field <- ["type", "tenant", "user", "mode", "database"] do
        assert {:error, :invalid_token} = PoolId.decode_token(token(%{field => nil}))
      end
    end

    test "rejects JSON that is not an object" do
      assert {:error, :invalid_token} = PoolId.decode_token(Base.url_encode64("[1]"))
    end
  end
end
