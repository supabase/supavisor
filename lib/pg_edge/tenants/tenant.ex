defmodule PgEdge.Tenants.Tenant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @schema_prefix "pgedge"

  schema "tenants" do
    field(:db_database, :string)
    field(:db_host, :string)
    field(:db_password, PgEdge.Encrypted.Binary)
    field(:db_port, :integer)
    field(:db_user, :string)
    field(:external_id, :string)
    field(:pool_size, :integer)

    timestamps()
  end

  @doc false
  def changeset(tenant, attrs) do
    tenant
    |> cast(attrs, [
      :external_id,
      :db_host,
      :db_port,
      :db_user,
      :db_database,
      :db_password,
      :pool_size
    ])
    |> validate_required([
      :external_id,
      :db_host,
      :db_port,
      :db_user,
      :db_database,
      :db_password,
      :pool_size
    ])
  end
end
