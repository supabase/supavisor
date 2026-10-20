defmodule SupavisorWeb.PoolId do
  @moduledoc """
  API representation of a `Supavisor.id`: a readable map, and an opaque token that
  clients echo back to target a pool.

  The token is URL-safe Base64 of the id's JSON. It is not a secret (the API is
  authenticated) and is decoded through an embedded schema, so enum fields are cast
  to known atoms rather than created with `String.to_atom/1`.
  """

  use Ecto.Schema

  import Ecto.Changeset
  require Supavisor

  @type id :: %{
          type: :single | :cluster,
          tenant: String.t(),
          user: String.t(),
          mode: :transaction | :session,
          database: String.t(),
          search_path: String.t() | nil,
          upstream_tls: boolean()
        }

  # Pools are only started in the listener modes; `:proxy` is a client-side state.
  @primary_key false
  embedded_schema do
    field(:type, Ecto.Enum, values: [:single, :cluster])
    field(:tenant, :string)
    field(:user, :string)
    field(:mode, Ecto.Enum, values: [:transaction, :session])
    field(:database, :string)
    field(:search_path, :string)
    field(:upstream_tls, :boolean, default: false)
  end

  @required [:type, :tenant, :user, :mode, :database]
  @optional [:search_path, :upstream_tls]

  @spec id_to_map(Supavisor.id()) :: id()
  def id_to_map(
        Supavisor.id(
          type: type,
          tenant: tenant,
          user: user,
          mode: mode,
          db: db,
          search_path: search_path,
          upstream_tls: upstream_tls
        )
      ) do
    %{
      type: type,
      tenant: tenant,
      user: user,
      mode: mode,
      database: db,
      search_path: search_path,
      upstream_tls: upstream_tls
    }
  end

  @spec encode_token(Supavisor.id()) :: String.t()
  def encode_token(id) do
    id
    |> id_to_map()
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  @spec decode_token(term()) :: {:ok, Supavisor.id()} | {:error, :invalid_token}
  def decode_token(token) when is_binary(token) do
    with {:ok, json} <- Base.url_decode64(token, padding: false),
         {:ok, %{} = map} <- Jason.decode(json),
         {:ok, id} <- parse_id(map) do
      {:ok, id}
    else
      _ -> {:error, :invalid_token}
    end
  end

  def decode_token(_), do: {:error, :invalid_token}

  defp parse_id(map) do
    with {:ok, parsed} <-
           %__MODULE__{}
           |> cast(map, @required ++ @optional)
           |> validate_required(@required)
           |> apply_action(:parse) do
      {:ok,
       Supavisor.id(
         type: parsed.type,
         tenant: parsed.tenant,
         user: parsed.user,
         mode: parsed.mode,
         db: parsed.database,
         search_path: parsed.search_path,
         upstream_tls: parsed.upstream_tls
       )}
    end
  end
end
