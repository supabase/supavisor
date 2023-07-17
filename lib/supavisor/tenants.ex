defmodule Supavisor.Tenants do
  @moduledoc """
  The Tenants context.
  """

  import Ecto.Query, warn: false
  alias Supavisor.Repo

  alias Supavisor.Tenants.Tenant
  alias Supavisor.Tenants.User

  @doc """
  Returns the list of tenants.

  ## Examples

      iex> list_tenants()
      [%Tenant{}, ...]

  """
  def list_tenants do
    Repo.all(Tenant) |> Repo.preload([:users])
  end

  @doc """
  Gets a single tenant.

  Raises `Ecto.NoResultsError` if the Tenant does not exist.

  ## Examples

      iex> get_tenant!(123)
      %Tenant{}

      iex> get_tenant!(456)
      ** (Ecto.NoResultsError)

  """
  def get_tenant!(id), do: Repo.get!(Tenant, id)

  @spec get_tenant_by_external_id(String.t()) :: Tenant.t() | nil
  def get_tenant_by_external_id(external_id) do
    Tenant |> Repo.get_by(external_id: external_id) |> Repo.preload(:users)
  end

  @spec get_user(String.t(), String.t() | nil) ::
          {:ok, map()} | {:error, :not_found | :multiple_results}
  def get_user(external_id, user) do
    query = build_user_query(external_id, user)

    case Repo.all(query) do
      nil ->
        {:error, :not_found}

      [{%User{}, %Tenant{}} = {user, tenant}] ->
        {:ok, %{user: user, tenant: tenant}}

      [] ->
        get_auth_user(external_id)

      _ ->
        {:error, :multiple_results}
    end
  end

  def get_auth_user(external_id) do
    query =
      from(t in Tenant,
        join: u in User,
        on: u.tenant_external_id == t.external_id,
        where: t.external_id == ^external_id and t.require_user == false,
        select: {u, t}
      )

    case Repo.all(query) do
      [{%User{}, %Tenant{}} = {user, tenant}] ->
        {:ok, %{user: user, tenant: tenant}}

      _ ->
        {:error, :not_found}
    end
  end

  def get_pool_config(external_id, user) do
    query =
      from(a in User,
        where: a.db_user_alias == ^user
      )

    Repo.one(
      from(p in Tenant,
        where: p.external_id == ^external_id,
        preload: [users: ^query]
      )
    )
  end

  @doc """
  Creates a tenant.

  ## Examples

      iex> create_tenant(%{field: value})
      {:ok, %Tenant{}}

      iex> create_tenant(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_tenant(attrs \\ %{}) do
    %Tenant{}
    |> Tenant.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a tenant.

  ## Examples

      iex> update_tenant(tenant, %{field: new_value})
      {:ok, %Tenant{}}

      iex> update_tenant(tenant, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_tenant(%Tenant{} = tenant, attrs) do
    tenant
    |> Tenant.changeset(attrs)
    |> Repo.update()
  end

  def update_tenant_ps(external_id, new_ps) do
    from(t in Tenant, where: t.external_id == ^external_id)
    |> Repo.one()
    |> Tenant.changeset(%{default_parameter_status: new_ps})
    |> Repo.update()
  end

  @doc """
  Deletes a tenant.

  ## Examples

      iex> delete_tenant(tenant)
      {:ok, %Tenant{}}

      iex> delete_tenant(tenant)
      {:error, %Ecto.Changeset{}}

  """
  def delete_tenant(%Tenant{} = tenant) do
    Repo.delete(tenant)
  end

  @spec delete_tenant_by_external_id(String.t()) :: boolean()
  def delete_tenant_by_external_id(id) do
    from(t in Tenant, where: t.external_id == ^id)
    |> Repo.delete_all()
    |> case do
      {num, _} when num > 0 ->
        true

      _ ->
        false
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking tenant changes.

  ## Examples

      iex> change_tenant(tenant)
      %Ecto.Changeset{data: %Tenant{}}

  """
  def change_tenant(%Tenant{} = tenant, attrs \\ %{}) do
    Tenant.changeset(tenant, attrs)
  end

  alias Supavisor.Tenants.User

  @doc """
  Returns the list of users.

  ## Examples

      iex> list_users()
      [%User{}, ...]

  """
  def list_users do
    Repo.all(User)
  end

  @doc """
  Creates a user.

  ## Examples

      iex> create_user(%{field: value})
      {:ok, %User{}}

      iex> create_user(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_user(attrs \\ %{}) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a user.

  ## Examples

      iex> update_user(user, %{field: new_value})
      {:ok, %User{}}

      iex> update_user(user, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_user(%User{} = user, attrs) do
    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a user.

  ## Examples

      iex> delete_user(user)
      {:ok, %User{}}

      iex> delete_user(user)
      {:error, %Ecto.Changeset{}}

  """
  def delete_user(%User{} = user) do
    Repo.delete(user)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking user changes.

  ## Examples

      iex> change_user(user)
      %Ecto.Changeset{data: %User{}}

  """
  def change_user(%User{} = user, attrs \\ %{}) do
    User.changeset(user, attrs)
  end

  @spec build_user_query(String.t(), String.t() | nil) :: Ecto.Queryable.t()
  defp build_user_query(external_id, user) do
    query =
      from(u in User,
        join: t in Tenant,
        on: u.tenant_external_id == t.external_id,
        where: u.tenant_external_id == ^external_id,
        select: {u, t}
      )

    if user do
      from(u in query,
        where: u.db_user_alias == ^user
      )
    else
      query
    end
  end
end
