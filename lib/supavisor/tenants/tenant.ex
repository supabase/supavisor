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
    field(:default_parameter_status, :map)
    field(:ip_version, Ecto.Enum, values: [:v4, :v6, :auto], default: :auto)
    field(:upstream_ssl, :boolean, default: false)
    field(:upstream_verify, Ecto.Enum, values: [:none, :peer])
    field(:upstream_tls_ca, Supavisor.Encrypted.Binary, source: :upstream_tls_ca_encrypted)

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
      :default_parameter_status,
      :external_id,
      :db_host,
      :db_port,
      :db_database,
      :ip_version,
      :upstream_ssl,
      :upstream_verify,
      :upstream_tls_ca
    ])
    |> check_constraint(:upstream_ssl, name: :upstream_constraints, prefix: "_supavisor")
    |> check_constraint(:upstream_verify, name: :upstream_constraints, prefix: "_supavisor")
    |> check_constraint(:upstream_tls_ca,
      name: :upstream_constraints,
      prefix: "_supavisor"
    )
    |> validate_required([
      :default_parameter_status,
      :external_id,
      :db_host,
      :db_port,
      :db_database
    ])
    |> unique_constraint([:external_id])
    |> cast_assoc(:users, with: &User.changeset/2)
  end
end
