defmodule Supavisor.HttpSql.NeonBodyParserTest do
  use ExUnit.Case, async: true
  use Plug.Test

  @subject Supavisor.HttpSql.NeonBodyParser

  defp init, do: @subject.init(json_decoder: Jason)

  defp post(path, body, headers \\ []) do
    conn = conn(:post, path, body)
    Enum.reduce(headers, conn, fn {h, v}, acc -> put_req_header(acc, h, v) end)
  end

  describe "trigger predicate" do
    test "fires on POST /sql with Neon-Connection-String, no Content-Type" do
      conn =
        post(
          "/sql",
          ~s({"query":"SELECT 1","params":[]}),
          [{"neon-connection-string", "postgres://u:p@h/d"}]
        )
        |> @subject.call(init())

      assert conn.body_params == %{"query" => "SELECT 1", "params" => []}
    end

    test "passes through POST /sql without Neon-Connection-String" do
      conn =
        post("/sql", ~s({"query":"SELECT 1"}), [])
        |> @subject.call(init())

      assert %Plug.Conn.Unfetched{} = conn.body_params
    end

    test "passes through POST /api/foo even with Neon-Connection-String header" do
      conn =
        post(
          "/api/foo",
          ~s({"hello":"world"}),
          [{"neon-connection-string", "postgres://u:p@h/d"}]
        )
        |> @subject.call(init())

      assert %Plug.Conn.Unfetched{} = conn.body_params
    end

    test "passes through GET /sql (only POST is intercepted)" do
      conn =
        conn(:get, "/sql")
        |> put_req_header("neon-connection-string", "postgres://u:p@h/d")
        |> @subject.call(init())

      assert %Plug.Conn.Unfetched{} = conn.body_params
    end
  end

  describe "body parsing regardless of Content-Type" do
    for ct <- ["text/plain", "application/octet-stream", "application/json"] do
      test "parses JSON with Content-Type #{ct}" do
        conn =
          post(
            "/sql",
            ~s({"query":"SELECT 1"}),
            [
              {"neon-connection-string", "postgres://u:p@h/d"},
              {"content-type", unquote(ct)}
            ]
          )
          |> @subject.call(init())

        assert conn.body_params == %{"query" => "SELECT 1"}
      end
    end

    test "parses complex nested JSON" do
      body =
        ~s({"queries":[{"query":"SELECT $1","params":[42]},{"query":"SELECT $1","params":["x"]}]})

      conn =
        post("/sql", body, [{"neon-connection-string", "postgres://u:p@h/d"}])
        |> @subject.call(init())

      assert %{"queries" => [_, _]} = conn.body_params
    end

    test "empty body → empty params" do
      conn =
        post("/sql", "", [{"neon-connection-string", "postgres://u:p@h/d"}])
        |> @subject.call(init())

      assert conn.body_params == %{}
    end

    test "JSON scalar wrapped under _json key" do
      conn =
        post("/sql", "42", [{"neon-connection-string", "postgres://u:p@h/d"}])
        |> @subject.call(init())

      assert conn.body_params == %{"_json" => 42}
    end

    test "JSON array wrapped under _json key" do
      conn =
        post("/sql", "[1,2,3]", [{"neon-connection-string", "postgres://u:p@h/d"}])
        |> @subject.call(init())

      assert conn.body_params == %{"_json" => [1, 2, 3]}
    end
  end

  describe "error handling" do
    test "invalid JSON raises Plug.Parsers.ParseError" do
      assert_raise Plug.Parsers.ParseError, fn ->
        post(
          "/sql",
          "{not valid json}",
          [{"neon-connection-string", "postgres://u:p@h/d"}]
        )
        |> @subject.call(init())
      end
    end

    test "leaves conn alone when body_params is already a map" do
      # Mirrors the case where Plug.Test set params directly, or an
      # upstream plug already parsed the body.
      conn =
        post(
          "/sql",
          "this would be invalid JSON",
          [{"neon-connection-string", "postgres://u:p@h/d"}]
        )

      conn = %{conn | body_params: %{"prearranged" => true}}
      result = @subject.call(conn, init())
      assert result.body_params == %{"prearranged" => true}
    end
  end

  describe "init/1" do
    test "requires :json_decoder" do
      assert_raise KeyError, fn -> @subject.init([]) end
    end

    test "accepts atom module as decoder" do
      state = @subject.init(json_decoder: Jason)
      assert state.decoder == {Jason, :decode!, []}
    end

    test "accepts {mod, fun, args} tuple decoder" do
      state = @subject.init(json_decoder: {Jason, :decode!, []})
      assert state.decoder == {Jason, :decode!, []}
    end

    test "extracts read_body opts" do
      state = @subject.init(json_decoder: Jason, length: 1024, read_length: 256)
      assert state.read_body_opts[:length] == 1024
      assert state.read_body_opts[:read_length] == 256
    end
  end

  describe "params merging" do
    test "preserves existing query-string params" do
      conn = %{
        conn(:post, "/sql?a=1", ~s({"b":"2"}))
        | params: %{"a" => "1"}
      }
      |> put_req_header("neon-connection-string", "postgres://u:p@h/d")
      |> @subject.call(init())

      assert conn.params == %{"a" => "1", "b" => "2"}
      assert conn.body_params == %{"b" => "2"}
    end
  end
end
