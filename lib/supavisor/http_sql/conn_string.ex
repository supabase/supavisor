defmodule Supavisor.HttpSql.ConnString do
  @moduledoc """
  Parses the `Neon-Connection-String` HTTP header into the fields Supavisor
  needs to authenticate an HTTP /sql request: `user`, `password`, `database`,
  and the candidate `external_id` extracted from Supabase's tenant-in-username
  convention (`postgres.<external_id>`).

  The header carries a standard Postgres connection URL, e.g.

      postgres://postgres.dev_tenant:secret@host:5432/postgres

  We do NOT validate that the user or tenant exists — that is the caller's
  responsibility via `Supavisor.Tenants.get_user_cache/4`.
  """

  @type parsed :: %{
          user: String.t(),
          password: String.t(),
          database: String.t() | nil,
          external_id: String.t() | nil
        }

  @type error ::
          :missing_url | :malformed | :unsupported_scheme | :missing_user | :missing_password

  @doc """
  Parse a Neon-style Postgres connection URL.

  Returns `{:ok, %{user, password, database, external_id}}` on success or
  `{:error, reason}` for malformed input. The `external_id` is `nil` when the
  username does not match the Supabase `<role>.<id>` or `<role>:<id>` form.

  ## Examples

      iex> Supavisor.HttpSql.ConnString.parse("postgres://postgres.acme:s3cret@h/db")
      {:ok, %{user: "postgres.acme", password: "s3cret", database: "db", external_id: "acme"}}

      iex> Supavisor.HttpSql.ConnString.parse("postgresql://u:p%40ss@h/d")
      {:ok, %{user: "u", password: "p@ss", database: "d", external_id: nil}}

      iex> Supavisor.HttpSql.ConnString.parse(nil)
      {:error, :missing_url}

      iex> Supavisor.HttpSql.ConnString.parse("http://u:p@h/d")
      {:error, :unsupported_scheme}
  """
  @spec parse(String.t() | nil) :: {:ok, parsed} | {:error, error}
  def parse(nil), do: {:error, :missing_url}
  def parse(""), do: {:error, :missing_url}

  def parse(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme} when scheme not in ["postgres", "postgresql"] ->
        {:error, :unsupported_scheme}

      %URI{userinfo: nil} ->
        {:error, :missing_user}

      %URI{userinfo: userinfo, path: path} = uri ->
        with {:ok, user, password} <- split_userinfo(userinfo),
             :ok <- ensure_host(uri) do
          {:ok,
           %{
             user: user,
             password: password,
             database: extract_database(path),
             external_id: extract_external_id(user)
           }}
        end
    end
  rescue
    _ -> {:error, :malformed}
  end

  defp split_userinfo(userinfo) do
    case String.split(userinfo, ":", parts: 2) do
      [user, password] when user != "" and password != "" ->
        {:ok, URI.decode(user), URI.decode(password)}

      [user] when user != "" ->
        {:error, :missing_password}

      _ ->
        {:error, :missing_user}
    end
  end

  defp ensure_host(%URI{host: nil}), do: {:error, :malformed}
  defp ensure_host(%URI{host: ""}), do: {:error, :malformed}
  defp ensure_host(_), do: :ok

  defp extract_database(nil), do: nil
  defp extract_database("/"), do: nil
  defp extract_database("/" <> rest), do: rest
  defp extract_database(other), do: other

  defp extract_external_id(user) do
    case String.split(user, ".", parts: 2) do
      [_role, ""] -> nil
      [_role, ext] -> ext
      [_only] -> nil
    end
  end
end
