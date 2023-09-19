defmodule SupavisorWeb.ClusterController do
  use SupavisorWeb, :controller

  alias Supavisor.Tenants
  alias Supavisor.Tenants.Cluster

  action_fallback(SupavisorWeb.FallbackController)

  def index(conn, _params) do
    clusters = Tenants.list_clusters()
    render(conn, :index, clusters: clusters)
  end

  def create(conn, %{"cluster" => cluster_params}) do
    IO.inspect({123, cluster_params})

    with {:ok, %Cluster{} = cluster} <- Tenants.create_cluster(cluster_params) do
      conn
      |> put_status(:created)
      # |> put_resp_header("location", ~p"/api/clusters/#{cluster}")
      |> render(:show, cluster: cluster)
    end
  end

  def show(conn, %{"id" => id}) do
    cluster = Tenants.get_cluster!(id)
    render(conn, :show, cluster: cluster)
  end

  def update(conn, %{"id" => id, "cluster" => cluster_params}) do
    cluster = Tenants.get_cluster!(id)

    with {:ok, %Cluster{} = cluster} <- Tenants.update_cluster(cluster, cluster_params) do
      render(conn, :show, cluster: cluster)
    end
  end

  def delete(conn, %{"id" => id}) do
    cluster = Tenants.get_cluster!(id)

    with {:ok, %Cluster{}} <- Tenants.delete_cluster(cluster) do
      send_resp(conn, :no_content, "")
    end
  end
end
