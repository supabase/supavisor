defmodule SupavisorWeb.PoolId do
  @moduledoc """
  External (API) representation of a `Supavisor.id`.

  A pool is identified internally by the `Supavisor.id` record. Over HTTP we expose
  it two ways:

    * as a readable map (`id_to_map/1`) for display and audit logs, and
    * as an opaque, reversible `token` (`encode_token/1` / `decode_token/1`) that a
      client echoes back to target a pool, so it needn't rebuild the id.

  The token is a URL-safe Base64 of the id's JSON — not a secret (auth is handled
  upstream), just a convenience. Decoding goes through the embedded-schema changeset
  below, so `type`/`mode` are cast to known atoms via `Ecto.Enum` (never
  `String.to_atom/1`) and a malformed token yields `{:error, _}` rather than a bad id.
  """

  use Ecto.Schema

  import Ecto.Changeset
  require Supavisor

  @type id_map :: %{
          type: atom(),
          tenant: String.t(),
          user: String.t(),
          mode: atom(),
          database: String.t(),
          search_path: String.t() | nil,
          upstream_tls: boolean()
        }

  # Not persisted — an embedded schema used only to validate/coerce the external id
  # form, mirroring `Supavisor.Tenants.User`/`Tenant` (cast + Ecto.Enum + validate).
  @primary_key false
  embedded_schema do
    field(:type, Ecto.Enum, values: [:single, :cluster])
    field(:tenant, :string)
    field(:user, :string)
    field(:mode, Ecto.Enum, values: [:transaction, :session, :native, :proxy])
    field(:database, :string)
    field(:search_path, :string)
    field(:upstream_tls, :boolean, default: false)
  end

  @required [:type, :tenant, :user, :mode, :database]
  @optional [:search_path, :upstream_tls]

  @doc "Serializes a `Supavisor.id` record to a JSON-friendly map."
  @spec id_to_map(Supavisor.id()) :: id_map()
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

  @doc "Encodes a `Supavisor.id` into an opaque, reversible token."
  @spec encode_token(Supavisor.id()) :: String.t()
  def encode_token(id) do
    id
    |> id_to_map()
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  @doc "Decodes a token produced by `encode_token/1` back into a validated `Supavisor.id`."
  @spec decode_token(String.t()) :: {:ok, Supavisor.id()} | {:error, term()}
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

  @doc """
  Builds a `Supavisor.id` from a string-keyed map (e.g. decoded JSON), validating
  enum and string fields via the embedded-schema changeset.
  """
  @spec parse_id(map()) :: {:ok, Supavisor.id()} | {:error, Ecto.Changeset.t() | :invalid_id}
  def parse_id(%{} = map) do
    %__MODULE__{}
    |> cast(map, @required ++ @optional)
    |> validate_required(@required)
    |> apply_action(:parse)
    |> case do
      {:ok, parsed} ->
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

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def parse_id(_), do: {:error, :invalid_id}
end
