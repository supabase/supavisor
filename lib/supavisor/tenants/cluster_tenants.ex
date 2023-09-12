defmodule Supavisor.Tenants.ClusterTenants do
  use Ecto.Schema
  import Ecto.Changeset
  alias Supavisor.Tenants.Tenant
  alias Supavisor.Tenants.Cluster

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @schema_prefix "_supavisor"

  schema "cluster_tenants" do
    field(:type, Ecto.Enum, values: [:write, :read])
    field(:is_active, :boolean)
    belongs_to(:cluster, Cluster, type: :string, foreign_key: :cluster_id)

    belongs_to(:tenant, Tenant,
      type: :string,
      foreign_key: :tenant_external_id,
      references: :external_id
    )

    timestamps()
  end

  @doc false
  def changeset(cluster, attrs) do
    cluster
    |> cast(attrs, [:type, :is_active, :cluster_id, :tenant_external_id])
    |> validate_required([:type, :is_active, :cluster_id, :tenant_external_id])

    # |> unique_constraint(:tenant_external_id)
  end
end
