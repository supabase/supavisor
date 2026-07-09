defmodule Supavisor.HttpSql.ConnStringTest do
  use ExUnit.Case, async: true

  doctest Supavisor.HttpSql.ConnString

  @subject Supavisor.HttpSql.ConnString

  describe "parse/1" do
    test "parses canonical Supabase URL" do
      assert {:ok,
              %{
                user: "postgres.dev_tenant",
                password: "secret",
                database: "postgres",
                external_id: "dev_tenant"
              }} =
               @subject.parse("postgres://postgres.dev_tenant:secret@localhost:6543/postgres")
    end

    test "accepts postgresql:// scheme" do
      assert {:ok, %{external_id: "acme"}} =
               @subject.parse("postgresql://postgres.acme:p@h/db")
    end

    test "URL-decodes the password" do
      assert {:ok, %{password: "p@ss/word"}} =
               @subject.parse("postgres://u:p%40ss%2Fword@h/db")
    end

    test "URL-decodes the username" do
      assert {:ok, %{user: "postgres.weird tenant"}} =
               @subject.parse("postgres://postgres.weird%20tenant:p@h/db")
    end

    test "returns external_id=nil when username has no separator" do
      assert {:ok, %{user: "postgres", external_id: nil}} =
               @subject.parse("postgres://postgres:p@h/db")
    end

    test "returns external_id=nil when separator is trailing with no id" do
      assert {:ok, %{external_id: nil}} =
               @subject.parse("postgres://postgres.:p@h/db")
    end

    test "returns database=nil when path is empty" do
      assert {:ok, %{database: nil}} = @subject.parse("postgres://u:p@h")
    end

    test "returns database=nil when path is bare slash" do
      assert {:ok, %{database: nil}} = @subject.parse("postgres://u:p@h/")
    end

    test "tolerates absent port" do
      assert {:ok, %{user: "u", password: "p", database: "d"}} =
               @subject.parse("postgres://u:p@host/d")
    end

    test "accepts IPv6 host literal" do
      assert {:ok, %{user: "u", password: "p"}} =
               @subject.parse("postgres://u:p@[::1]:6543/postgres")
    end

    test "rejects nil" do
      assert {:error, :missing_url} = @subject.parse(nil)
    end

    test "rejects empty string" do
      assert {:error, :missing_url} = @subject.parse("")
    end

    test "rejects non-postgres scheme" do
      assert {:error, :unsupported_scheme} = @subject.parse("http://u:p@h/d")
    end

    test "rejects mysql scheme" do
      assert {:error, :unsupported_scheme} = @subject.parse("mysql://u:p@h/d")
    end

    test "rejects URL with no userinfo" do
      assert {:error, :missing_user} = @subject.parse("postgres://host/db")
    end

    test "rejects URL with empty userinfo" do
      assert {:error, :missing_user} = @subject.parse("postgres://@host/db")
    end

    test "rejects URL with username but no password" do
      assert {:error, :missing_password} = @subject.parse("postgres://u@host/db")
    end

    test "rejects URL with empty password segment" do
      assert {:error, :missing_user} = @subject.parse("postgres://u:@host/db")
    end

    test "rejects URL with no host" do
      assert {:error, :malformed} = @subject.parse("postgres://u:p@/d")
    end

    test "extracts query-stringed databases (params discarded)" do
      assert {:ok, %{database: "postgres"}} =
               @subject.parse("postgres://u:p@h/postgres?sslmode=require")
    end
  end
end
