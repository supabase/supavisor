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
        tenant_external_id: %Schema{type: :string, description: "External Tenant ID"},
        db_user_alias: %Schema{type: :string, description: "Database user alias"},
        db_user: %Schema{type: :string, description: "Database user"},
        db_password: %Schema{type: :string, description: "Database password"},
        pool_size: %Schema{type: :integer, description: "Pool size"},
        mode_type: %Schema{type: :string, description: "Pooling mode type"},
        max_clients: %Schema{type: :integer, description: "Max clients count", nullable: true},
        pool_checkout_timeout: %Schema{type: :integer, description: "Pool checkout timeout"},
        is_manager: %Schema{
          type: :boolean,
          description: "The users who can be used for internal needs"
        },
        inserted_at: %Schema{type: :string, format: :date_time, readOnly: true},
        updated_at: %Schema{type: :string, format: :date_time, readOnly: true}
      },
      required: [
        :db_user,
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
        max_clients: 25_000,
        mode_type: "transaction",
        inserted_at: "2023-03-27T12:00:00Z",
        updated_at: "2023-03-27T12:00:00Z"
      }
    })

    def response, do: {"User Response", "application/json", __MODULE__}
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
        ip_version: %Schema{type: :string, description: "auto"},
        require_user: %Schema{type: :boolean, description: false},
        sni_hostname: %Schema{type: :string, description: "your.domain.com", nullable: true},
        upstream_ssl: %Schema{type: :boolean, description: true},
        upstream_verify: %Schema{type: :string, description: "none", nullable: true},
        enforce_ssl: %Schema{type: :boolean, description: false},
        allow_list: %Schema{
          type: :array,
          description: "List of CIDR addresses",
          items: %Schema{type: :string}
        },
        auth_query: %Schema{
          type: :string,
          description: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
          nullable: true
        },
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
        allow_list: ["0.0.0.0/0", "::/0"],
        users: [
          %{
            id: "b1024a4c-4eb4-4c64-8f49-c8a46c2b2e16",
            external_id: "dev_tenant",
            db_user_alias: "postgres",
            db_user: "postgres",
            db_password: "postgres",
            pool_size: 10,
            max_clients: 25_000,
            pool_checkout_timeout: 1000,
            is_manager: false,
            mode_type: "transaction",
            inserted_at: "2023-03-27T12:00:00Z",
            updated_at: "2023-03-27T12:00:00Z"
          }
        ]
      }
    })

    def response, do: {"Tenant Response", "application/json", __MODULE__}
  end

  defmodule TenantData do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{type: :object, properties: %{data: Tenant}, required: [:data]})

    def response, do: {"Tenant Show Response", "application/json", __MODULE__}
  end

  defmodule TenantList do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{type: :array, items: Tenant})
    def response, do: {"Tenant List Response", "application/json", __MODULE__}
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
            ip_version: %Schema{type: :string, description: "auto"},
            require_user: %Schema{type: :boolean, description: false},
            sni_hostname: %Schema{type: :string, description: "your.domain.com"},
            upstream_ssl: %Schema{type: :boolean, description: true},
            upstream_verify: %Schema{type: :string, description: "none"},
            enforce_ssl: %Schema{type: :boolean, description: false},
            auth_query: %Schema{
              type: :string,
              description: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1"
            },
            users: %Schema{type: :array, items: User},
            inserted_at: %Schema{type: :string, format: :date_time, readOnly: true},
            updated_at: %Schema{type: :string, format: :date_time, readOnly: true},
            allow_list: %Schema{
              type: :array,
              description: "List of CIDR addresses",
              default: ["0.0.0.0/0", "::/0"]
            }
          },
          required: [
            :db_host,
            :db_port,
            :db_database,
            :users,
            :require_user
          ],
          example: %{
            db_host: "localhost",
            db_port: 5432,
            db_database: "postgres",
            ip_version: "auto",
            enforce_ssl: false,
            require_user: true,
            allow_list: ["0.0.0.0/0", "::/0"],
            users: [
              %{
                db_user: "postgres",
                db_password: "postgres",
                pool_size: 10,
                mode_type: "transaction",
                max_clients: 25_000,
                pool_checkout_timeout: 1000
              }
            ]
          }
        }
      },
      required: [:tenant]
    })

    def params, do: {"Tenant Create Params", "application/json", __MODULE__}
  end

  defmodule Created do
    @moduledoc false
    def response(schema), do: {"Created Response", "application/json", schema}
  end

  defmodule Empty do
    @moduledoc false
    require OpenApiSpex
    OpenApiSpex.schema(%{})

    def response, do: {"", "application/json", __MODULE__}
  end

  defmodule NotFound do
    @moduledoc false
    require OpenApiSpex
    OpenApiSpex.schema(%{})

    def response, do: {"Not found", "application/json", __MODULE__}
  end

  defmodule BadRequest do
    @moduledoc false
    require OpenApiSpex
    OpenApiSpex.schema(%{})

    def response, do: {"Bad request", "application/json", __MODULE__}
  end

  defmodule ServiceUnavailable do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        status: %Schema{
          type: :string,
          description: "Supavisor health status",
          default: "unhealthy"
        },
        timestamp: %Schema{
          type: :string,
          format: :date_time,
          description: "Timestamp of the health check"
        },
        failed_checks: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "List of failed health check names"
        }
      }
    })

    def response, do: {"Service Unavailable", "application/json", __MODULE__}
  end

  defmodule UnprocessablyEntity do
    @moduledoc false
    require OpenApiSpex
    OpenApiSpex.schema(%{})

    def response, do: {"Unprocessable Entity", "application/json", __MODULE__}
  end

  defmodule UserCredentialsUpdate do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        db_user: %Schema{type: :string, description: "Database user"},
        db_password: %Schema{type: :string, description: "Database password"}
      },
      required: [:db_user, :db_password],
      example: %{
        db_user: "postgres",
        db_password: "new_password"
      }
    })

    def params, do: {"User Credentials Update Params", "application/json", __MODULE__}
  end

  defmodule NetworkBan do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        banned_address: %Schema{
          type: :string,
          description: "Banned IP address",
          example: "192.168.1.100"
        },
        banned_until: %Schema{
          type: :integer,
          minimum: 0,
          description: "Unix timestamp (seconds) when the ban expires"
        }
      },
      required: [:banned_address, :banned_until],
      example: %{
        banned_address: "192.168.1.100",
        banned_until: 1_706_549_400
      }
    })

    def response, do: {"Network Ban Response", "application/json", __MODULE__}
  end

  defmodule NetworkBanList do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        banned_ipv4_addresses: %Schema{
          type: :array,
          items: NetworkBan,
          description: "List of IP addresses banned due to authentication errors"
        }
      },
      required: [:banned_ipv4_addresses],
      example: %{
        banned_ipv4_addresses: [
          %{
            banned_address: "192.168.1.100",
            banned_until: 1_706_549_400
          },
          %{
            banned_address: "10.0.0.50",
            banned_until: 1_706_549_500
          }
        ]
      }
    })

    def response, do: {"Network Ban List Response", "application/json", __MODULE__}
  end

  defmodule ClearNetworkBans do
    @moduledoc false
    require OpenApiSpex

    OpenApiSpex.schema(%{
      type: :object,
      properties: %{
        ipv4_addresses: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "List of IPv4 addresses to unban",
          example: ["192.168.1.100", "10.0.0.50"]
        }
      },
      required: [:ipv4_addresses],
      example: %{
        ipv4_addresses: ["192.168.1.100", "10.0.0.50"]
      }
    })

    def params, do: {"Clear Network Ban Params", "application/json", __MODULE__}
  end
end
