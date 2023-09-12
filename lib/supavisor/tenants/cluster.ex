defmodule Supavisor.Tenants.Cluster do
  use Ecto.Schema
  import Ecto.Changeset
  # alias Supavisor.Tenants.ClusterTenants

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @schema_prefix "_supavisor"

  schema "clusters" do
    field(:is_active, :boolean)

    # has_many(:cluster_tenants, ClusterTenants,
    #   on_delete: :delete_all,
    #   on_replace: :delete
    # )

    timestamps()
  end

  @doc false
  def changeset(cluster, attrs) do
    cluster
    |> cast(attrs, [:cluster_tenants, :is_active])
    |> validate_required([:cluster_tenants, :is_active])

    # |> unique_constraint(:tenant_external_id)
  end
end
