defmodule Supavisor.Tenants.Cluster do
  use Ecto.Schema
  import Ecto.Changeset
  # alias Supavisor.Tenants.ClusterTenants

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @schema_prefix "_supavisor"

  schema "clusters" do
    field :active, :boolean, default: false

    timestamps()
  end

  @doc false
  def changeset(cluster, attrs) do
    cluster
    |> cast(attrs, [:active])
    |> validate_required([:active])
  end
end
