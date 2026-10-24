defmodule Supavisor.HttpSql do
  @moduledoc """
  SQL over HTTP, compatible with the HTTP mode of Neon's serverless driver (`@neondatabase/serverless`).

  This module exposes the `run/3` function, which takes the HTTP request body and headers,
  runs it using `Supavisor.HttpSql.Client`, and returns the HTTP response body.

  A request carries the connection string in the `Neon-Connection-String` header, and a JSON
  body with either one query, `{"query": sql, "params": [...]}`, or a batch run in one
  transaction, `{"queries": [{"query": sql, "params": [...]}, ...]}`.
  """

  alias Supavisor.HttpSql.Client
  alias Supavisor.Protocol.StartupOptions

  @type query() :: {String.t(), [String.t() | nil]}

  @type conn_info() :: %{
          user: String.t(),
          password: String.t(),
          database: String.t(),
          application_name: String.t() | nil,
          options: %{String.t() => String.t()}
        }

  @type result() :: %{
          fields: [map()],
          # The JSON rows, separated by commas
          rows: binary(),
          command: String.t() | nil,
          row_count: non_neg_integer() | nil
        }

  @isolation_levels %{
    "ReadUncommitted" => "READ UNCOMMITTED",
    "ReadCommitted" => "READ COMMITTED",
    "RepeatableRead" => "REPEATABLE READ",
    "Serializable" => "SERIALIZABLE"
  }

  @error_fields %{
    "S" => "severity",
    "C" => "code",
    "D" => "detail",
    "H" => "hint",
    "P" => "position",
    "p" => "internalPosition",
    "q" => "internalQuery",
    "W" => "where",
    "s" => "schema",
    "t" => "table",
    "c" => "column",
    "d" => "dataType",
    "n" => "constraint",
    "F" => "file",
    "L" => "line",
    "R" => "routine"
  }

  @doc """
  Runs a request, returning its JSON response body.
  """
  @spec run(String.t() | nil, map(), %{String.t() => String.t()}, String.t()) ::
          {:ok, iodata()} | {:error, {:postgres, iodata()} | {:bad_request, String.t()} | term()}
  def run(conn_string, body, headers, client_ip) do
    with {:ok, conn_info} <- parse_connection_string(conn_string),
         {:ok, request} <- parse_body(body),
         {:ok, begin} <- begin_statement(request, headers),
         {:ok, results} <- Client.run(conn_info, client_ip, queries(request, begin)) do
      {:ok, response(request, begin, results)}
    else
      {:error, {:postgres, error}} -> {:error, {:postgres, error_json(error)}}
      error -> error
    end
  end

  # Parses the `Neon-Connection-String` header.
  defp parse_connection_string(nil),
    do: {:error, {:bad_request, "missing Neon-Connection-String header"}}

  defp parse_connection_string(conn_string) do
    with %URI{scheme: scheme, userinfo: userinfo, path: "/" <> database} = uri
         when scheme in ["postgres", "postgresql"] and is_binary(userinfo) and database != "" <-
           URI.parse(conn_string),
         [user, password] <- String.split(userinfo, ":", parts: 2) do
      query = URI.decode_query(uri.query || "")

      {:ok,
       %{
         user: URI.decode(user),
         password: URI.decode(password),
         database: URI.decode(database),
         application_name: query["application_name"],
         options: decode_options(query["options"])
       }}
    else
      _ -> {:error, {:bad_request, "invalid Neon-Connection-String header"}}
    end
  end

  # Like Supavisor does: `-c name=value` arguments, or else a query string like `reference=x`.
  defp decode_options(nil), do: %{}

  defp decode_options(options) do
    case StartupOptions.parse(options) do
      parsed when map_size(parsed) > 0 -> parsed
      _ -> URI.decode_query(options, %{}, :rfc3986)
    end
  end

  # Parses the request body into a single query or a batch.
  defp parse_body(%{"queries" => queries}) when is_list(queries) do
    queries
    |> Enum.reduce_while({:ok, []}, fn query, {:ok, acc} ->
      case parse_query(query) do
        {:ok, query} -> {:cont, {:ok, [query | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, queries} -> {:ok, {:batch, Enum.reverse(queries)}}
      error -> error
    end
  end

  defp parse_body(body) do
    with {:ok, query} <- parse_query(body), do: {:ok, {:single, query}}
  end

  defp parse_query(%{"query" => sql} = query) when is_binary(sql) do
    case parse_params(Map.get(query, "params", [])) do
      {:ok, params} -> {:ok, {sql, params}}
      :error -> {:error, {:bad_request, "params must be strings, numbers, booleans or null"}}
    end
  end

  defp parse_query(_), do: {:error, {:bad_request, "invalid request body"}}

  # Converts params to strings.
  defp parse_params(params) when is_list(params) do
    Enum.reduce_while(params, {:ok, []}, fn
      param, {:ok, acc} when is_binary(param) or is_nil(param) -> {:cont, {:ok, [param | acc]}}
      param, {:ok, acc} when is_number(param) -> {:cont, {:ok, [to_string(param) | acc]}}
      param, {:ok, acc} when is_boolean(param) -> {:cont, {:ok, [to_string(param) | acc]}}
      _param, _acc -> {:halt, :error}
    end)
    |> case do
      {:ok, params} -> {:ok, Enum.reverse(params)}
      :error -> :error
    end
  end

  defp parse_params(_), do: :error

  # Builds the statement opening a batch's transaction from the `Neon-Batch-*` headers.
  defp begin_statement({:single, _query}, _headers), do: {:ok, nil}

  defp begin_statement({:batch, _queries}, headers) do
    case Map.fetch(headers, "neon-batch-isolation-level") do
      :error ->
        {:ok, Enum.join(["BEGIN" | access_modes(headers)], " ")}

      {:ok, level} when is_map_key(@isolation_levels, level) ->
        isolation = ["ISOLATION LEVEL", @isolation_levels[level]]
        {:ok, Enum.join(["BEGIN" | isolation ++ access_modes(headers)], " ")}

      {:ok, _level} ->
        {:error, {:bad_request, "invalid Neon-Batch-Isolation-Level header"}}
    end
  end

  defp access_modes(headers) do
    read_only =
      case headers["neon-batch-read-only"] do
        "true" -> ["READ ONLY"]
        "false" -> ["READ WRITE"]
        _ -> []
      end

    deferrable =
      case headers["neon-batch-deferrable"] do
        "true" -> ["DEFERRABLE"]
        "false" -> ["NOT DEFERRABLE"]
        _ -> []
      end

    read_only ++ deferrable
  end

  defp queries({:single, query}, nil), do: [query]
  defp queries({:batch, queries}, begin), do: [{begin, []} | queries] ++ [{"COMMIT", []}]

  defp response({:single, _query}, nil, [result]),
    do: Jason.encode_to_iodata!(result_json(result))

  defp response({:batch, _queries}, _begin, results) do
    # Drops the results of BEGIN and COMMIT.
    results = results |> Enum.drop(1) |> Enum.drop(-1)
    Jason.encode_to_iodata!(%{"results" => Enum.map(results, &result_json/1)})
  end

  # Builds the JSON for a query's result.
  defp result_json(result) do
    %{
      "fields" => Enum.map(result.fields, &field_json/1),
      "rows" => Jason.Fragment.new(["[", result.rows, "]"]),
      "command" => result.command,
      "rowCount" => result.row_count,
      "rowAsArray" => true
    }
  end

  defp field_json(field) do
    %{
      "name" => field.name,
      "tableID" => field.table_oid,
      "columnID" => field.attr_number,
      "dataTypeID" => field.data_type_oid,
      "dataTypeSize" => field.data_type_size,
      "dataTypeModifier" => field.type_modifier,
      "format" => "text"
    }
  end

  # Builds the JSON for an error returned by Postgres.
  defp error_json(error) do
    error =
      for {key, name} <- @error_fields,
          Map.has_key?(error, key),
          into: %{"message" => error["M"]},
          do: {name, error[key]}

    JSON.encode_to_iodata!(error)
  end
end
