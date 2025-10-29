defmodule SupavisorWeb.TenantController do
  use SupavisorWeb, :controller
  use OpenApiSpex.ControllerSpecs

  require Logger

  alias Supavisor.{
    Helpers,
    Repo,
    Tenants
  }

  alias Tenants.Tenant, as: TenantModel

  alias SupavisorWeb.OpenApiSchemas.{
    BadRequest,
    Created,
    Empty,
    NotFound,
    ServiceUnavailable,
    Tenant,
    TenantCreate,
    TenantData,
    TenantList,
    UnprocessablyEntity,
    UserCredentialsUpdate
  }

  action_fallback(SupavisorWeb.FallbackController)

  @authorization [
    in: :header,
    name: "Authorization",
    schema: %OpenApiSpex.Schema{type: :string},
    required: true,
    example:
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2ODAxNjIxNTR9.U9orU6YYqXAtpF8uAiw6MS553tm4XxRzxOhz2IwDhpY"
  ]

  operation(:index,
    summary: "List tenants",
    parameters: [authorization: @authorization],
    responses: %{
      200 => TenantList.response()
    }
  )

  def index(conn, _params) do
    tenants = Tenants.list_tenants()
    render(conn, "index.json", tenants: tenants)
  end

  operation(:create,
    summary: "Create tenant",
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    request_body: TenantCreate.params(),
    responses: %{
      201 => TenantData.response(),
      422 => UnprocessablyEntity.response()
    }
  )

  def create(conn, %{"tenant" => tenant_params}) do
    with {:ok, %TenantModel{} = tenant} <- Tenants.create_tenant(tenant_params) do
      conn
      |> put_status(:created)
      |> put_resp_header("location", Routes.tenant_path(conn, :show, tenant))
      |> render("show.json", tenant: tenant)
    end
  end

  operation(:show,
    summary: "Fetch Tenant",
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    request_body: TenantCreate.params(),
    responses: %{
      200 => TenantData.response(),
      404 => NotFound.response()
    }
  )

  def show(conn, %{"external_id" => id}) do
    id
    |> Tenants.get_tenant_by_external_id()
    |> case do
      %TenantModel{} = tenant ->
        render(conn, "show.json", tenant: tenant)

      nil ->
        conn
        |> put_status(404)
        |> render("not_found.json", tenant: nil)
    end
  end

  operation(:update,
    summary: "Create or update tenant",
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    request_body: TenantCreate.params(),
    responses: %{
      201 => Created.response(Tenant),
      400 => BadRequest.response(),
      404 => NotFound.response(),
      422 => UnprocessablyEntity.response()
    }
  )

  # convert cert to pem format
  def update(conn, %{
        "external_id" => id,
        "tenant" => %{"upstream_tls_ca" => "-----BEGIN" <> _ = upstream_tls_ca} = tenant_params
      }) do
    case Helpers.cert_to_bin(upstream_tls_ca) do
      {:ok, bin} ->
        update(conn, %{
          "external_id" => id,
          "tenant" => %{tenant_params | "upstream_tls_ca" => bin}
        })

      {:error, reason} ->
        conn
        |> put_status(400)
        |> render("error.json",
          error: "Invalid 'upstream_tls_ca' certificate, reason: #{inspect(reason)}"
        )
    end
  end

  def update(conn, %{"external_id" => id, "tenant" => params}) do
    cert = Helpers.upstream_cert(params["upstream_tls_ca"])

    if params["upstream_ssl"] && params["upstream_verify"] == "peer" && !cert do
      conn
      |> put_status(400)
      |> render("error.json",
        error: "Invalid 'upstream_verify' value, 'peer' is not allowed without certificate"
      )
    else
      case Tenants.get_tenant_by_external_id(id) do
        nil ->
          case Helpers.check_creds_get_ver(params) do
            {:error, reason} ->
              conn
              |> put_status(400)
              |> render("error.json", error: reason)

            {:ok, pg_version} ->
              params =
                if pg_version do
                  Map.put(params, "default_parameter_status", %{
                    "server_version" => pg_version
                  })
                else
                  params
                end

              create(conn, %{"tenant" => Map.put(params, "external_id", id)})
          end

        tenant ->
          tenant = Repo.preload(tenant, :users)

          with {:ok, %TenantModel{} = tenant} <-
                 Tenants.update_tenant_with_restart(tenant, params) do
            render(conn, "show.json", tenant: tenant)
          end
      end
    end
  end

  operation(:delete,
    summary: "Delete source",
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    responses: %{
      204 => Empty.response(),
      404 => NotFound.response()
    }
  )

  def delete(conn, %{"external_id" => id}) do
    code = if Tenants.delete_tenant_by_external_id(id), do: 204, else: 404

    Logger.info("Delete cache dist #{id}: #{inspect(Supavisor.del_all_cache_dist(id))}")

    send_resp(conn, code, "")
  end

  operation(:terminate,
    summary: "Stop tenant's pools and clear cache",
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    responses: %{
      204 => Empty.response(),
      404 => NotFound.response()
    }
  )

  def terminate(conn, %{"external_id" => external_id}) do
    Logger.metadata(project: external_id)
    result = Supavisor.terminate_global(external_id) |> inspect()
    Logger.warning("Terminate #{external_id}: #{result}")

    Logger.info(
      "Delete cache dist #{external_id}: #{inspect(Supavisor.del_all_cache_dist(external_id))}"
    )

    render(conn, "show_terminate.json", result: result)
  end

  operation(:health,
    summary: "Health check",
    parameters: [],
    responses: %{
      204 => Empty.response(),
      503 => ServiceUnavailable.response()
    }
  )

  def health(conn, _) do
    case Supavisor.Health.health_check() do
      :ok ->
        send_resp(conn, 204, "")

      {:error, :failed_checks, failed_checks} ->
        response = %{
          status: "unhealthy",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          failed_checks: Enum.map(failed_checks, &Atom.to_string/1)
        }

        conn
        |> put_status(503)
        |> json(response)
    end
  end

  operation(:update_auth_credentials,
    summary: "Update auth query credentials",
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    request_body: UserCredentialsUpdate.params(),
    responses: %{
      204 => Empty.response(),
      400 => BadRequest.response(),
      404 => NotFound.response(),
      422 => UnprocessablyEntity.response()
    }
  )

  def update_auth_credentials(conn, %{"external_id" => id} = params) do
    case Tenants.get_tenant_by_external_id(id) do
      nil ->
        conn
        |> put_status(404)
        |> render("not_found.json", tenant: nil)

      %TenantModel{require_user: true} ->
        conn
        |> put_status(400)
        |> render("error.json",
          error: "Cannot update credentials for tenants with require_user: true"
        )

      %TenantModel{require_user: false} = tenant ->
        case Tenants.update_manager_user_credentials(tenant, params) do
          :ok ->
            send_resp(conn, 204, "")

          {:error, :no_manager_user} ->
            conn
            |> put_status(400)
            |> render("error.json", error: "No manager user found for tenant")

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(422)
            |> put_view(SupavisorWeb.ChangesetView)
            |> render("error.json", changeset: changeset)
        end
    end
  end
end
