defmodule SupavisorWeb.OpenApiSchemas do
  @moduledoc """
  Providing schemas and response definitions for the OpenAPI specification of the SupavisorWeb
  """
  alias OpenApiSpex.Schema

  defmodule User do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        id: %Schema{type: :string, format: :binary_id, readOnly: true},
        tenant_external_id: %Schema{type: :string, description: "External Teanant ID"},
        db_user_alias: %Schema{type: :string, description: "Database user alias"},
        db_user: %Schema{type: :string, description: "Database user"},
        db_password: %Schema{type: :string, description: "Database password"},
        pool_size: %Schema{type: :integer, description: "Pool size"},
        mode_type: %Schema{type: :string, description: "Pooling mode type"},
        is_manager: %Schema{
          type: :boolean,
          description: "The users who can be used for internal needs"
        },
        inserted_at: %Schema{type: :string, format: :date_time, readOnly: true},
        updated_at: %Schema{type: :string, format: :date_time, readOnly: true}
      },
      required: [
        :db_host,
        :db_port,
        :db_user,
        :db_database,
        :db_password,
        :pool_size
      ],
      example: %{
        id: "b1024a4c-4eb4-4c64-8f49-c8a46c2b2e16",
        external_id: "dev_tenant",
        db_user_alias: "postgres",
        db_user: "postgres",
        db_password: "postgres",
        pool_size: 10,
        is_manager: false,
        mode_type: "transaction",
        inserted_at: "2023-03-27T12:00:00Z",
        updated_at: "2023-03-27T12:00:00Z"
      }
    })

    def response(), do: {"User Response", "application/json", __MODULE__}
  end

  defmodule Tenant do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        id: %Schema{type: :string, format: :binary_id, readOnly: true},
        external_id: %Schema{type: :string, description: "External ID"},
        db_host: %Schema{type: :string, description: "Database host"},
        db_port: %Schema{type: :integer, description: "Database port"},
        db_database: %Schema{type: :string, description: "Database name"},
        users: %Schema{type: :array, items: User},
        inserted_at: %Schema{type: :string, format: :date_time, readOnly: true},
        updated_at: %Schema{type: :string, format: :date_time, readOnly: true}
      },
      required: [
        :db_host,
        :db_port,
        :db_database,
        :users
      ],
      example: %{
        id: "b1024a4c-4eb4-4c64-8f49-c8a46c2b2e16",
        external_id: "dev_tenant",
        db_host: "localhost",
        db_port: 5432,
        db_database: "postgres",
        inserted_at: "2023-03-27T12:00:00Z",
        updated_at: "2023-03-27T12:00:00Z",
        users: [
          %{
            id: "b1024a4c-4eb4-4c64-8f49-c8a46c2b2e16",
            external_id: "dev_tenant",
            db_user_alias: "postgres",
            db_user: "postgres",
            db_password: "postgres",
            pool_size: 10,
            is_manager: false,
            mode_type: "transaction",
            inserted_at: "2023-03-27T12:00:00Z",
            updated_at: "2023-03-27T12:00:00Z"
          }
        ]
      }
    })

    def response(), do: {"Tenant Response", "application/json", __MODULE__}
  end

  defmodule TenantList do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{type: :array, items: Tenant})
    def response(), do: {"Tenant List Response", "application/json", __MODULE__}
  end

  defmodule TenantCreate do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        tenant: %Schema{
          type: :object,
          properties: %{
            id: %Schema{type: :string, format: :binary_id, readOnly: true},
            external_id: %Schema{type: :string, description: "External ID"},
            db_host: %Schema{type: :string, description: "Database host"},
            db_port: %Schema{type: :integer, description: "Database port"},
            db_database: %Schema{type: :string, description: "Database name"},
            users: %Schema{type: :array, items: User},
            inserted_at: %Schema{type: :string, format: :date_time, readOnly: true},
            updated_at: %Schema{type: :string, format: :date_time, readOnly: true}
          },
          required: [
            :db_host,
            :db_port,
            :db_database,
            :users
          ],
          example: %{
            db_host: "localhost",
            db_port: 5432,
            db_database: "postgres",
            users: [
              %{
                db_user: "postgres",
                db_password: "postgres",
                pool_size: 10,
                mode_type: "transaction"
              }
            ]
          }
        }
      },
      required: [:tenant]
    })

    def params(), do: {"Tenant Create Params", "application/json", __MODULE__}
  end

  defmodule Created do
    @moduledoc false
    def response(schema), do: {"Created Response", "application/json", schema}
  end

  defmodule Empty do
    @moduledoc false
    require OpenApiSpex
    OpenApiSpex.schema(%{})

    def response(), do: {"", "text/plain", __MODULE__}
  end

  defmodule NotFound do
    @moduledoc false
    require OpenApiSpex
    OpenApiSpex.schema(%{})

    def response(), do: {"Not found", "text/plain", __MODULE__}
  end
end
