defmodule Supavisor.Tenants.Tenant do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset
  alias Supavisor.Tenants.User

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @schema_prefix "_supavisor"

  schema "tenants" do
    field(:db_host, :string)
    field(:db_port, :integer)
    field(:db_database, :string)
    field(:external_id, :string)

    has_many(:users, User,
      foreign_key: :tenant_external_id,
      references: :external_id,
      on_delete: :delete_all,
      on_replace: :delete
    )

    timestamps()
  end

  @doc false
  def changeset(tenant, attrs) do
    tenant
    |> cast(attrs, [
      :external_id,
      :db_host,
      :db_port,
      :db_database
    ])
    |> validate_required([
      :external_id,
      :db_host,
      :db_port,
      :db_database
    ])
    |> unique_constraint([:external_id])
    |> cast_assoc(:users, with: &User.changeset/2)
  end
end
