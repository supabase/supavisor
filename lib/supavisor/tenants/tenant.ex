defmodule Supavisor.Tenants.Tenant do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @schema_prefix "supavisor"

  schema "tenants" do
    field(:db_database, :string)
    field(:db_host, :string)
    field(:db_password, Supavisor.Encrypted.Binary, source: :db_pass_encrypted)
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
    |> unique_constraint([:external_id])
  end
end
