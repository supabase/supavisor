#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration (overridable via environment variables)
POSTGRES_PORT=${POSTGRES_PORT:-7432}
POSTGRES_USER=${POSTGRES_USER:-postgres}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}
POSTGRES_DB=${POSTGRES_DB:-postgres}
TENANT_NAME=${TENANT_NAME:-"t2"}
DB_HOST=${DB_HOST:-"localhost"}
POOLER_PORT=${POOLER_PORT:-5432}
POOLER_API=${POOLER_API:-"http://localhost:4000"}
BEARER_TOKEN=${BEARER_TOKEN:-"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.M9jrxyvPLkUxWgOYSf5dNdJ8v_eRrq810ShFRT8N-6M"}
CONTAINER_NAME_PG15=${CONTAINER_NAME_PG15:-"test_postgres_15"}
CONTAINER_NAME_PG16=${CONTAINER_NAME_PG16:-"test_postgres_16"}

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to wait for PostgreSQL to be ready
wait_for_postgres() {
    local container_name=$1
    local max_attempts=30
    local attempt=1

    print_status "Waiting for PostgreSQL to be ready..."

    while [ $attempt -le $max_attempts ]; do
        if PGPASSWORD=$POSTGRES_PASSWORD pg_isready -h localhost -p $POSTGRES_PORT -U $POSTGRES_USER -d $POSTGRES_DB >/dev/null 2>&1; then
            print_status "PostgreSQL is ready!"
            return 0
        fi

        echo -n "."
        sleep 1
        ((attempt++))
    done

    print_error "PostgreSQL failed to start within $max_attempts seconds"
    return 1
}

# Function to generate psql connection URL
generate_psql_url() {
    local pooler=$1
    local user=$POSTGRES_USER
    local host=$DB_HOST
    local database=$POSTGRES_DB

    if [ "$pooler" = true ]; then
        echo "postgres://${user}.${TENANT_NAME}@${host}:${POOLER_PORT}/${database}"
    else
        echo "postgres://${user}@${host}:${POSTGRES_PORT}/${database}"
    fi
}

# Function to run a test query
run_test_query() {
    local container_name=$1
    local version=$2
    local pooler=$3
    local pooler_text=""

    if [ "$pooler" = true ]; then
        pooler_text=" (via pooler)"
    fi

    print_status "Running test query on PostgreSQL $version$pooler_text..."

    local psql_url=$(generate_psql_url $pooler)

    print_status "Connection URL: $psql_url"

    # Query the data back
    print_status "Querying data from PostgreSQL $version$pooler_text:"
    PGPASSWORD=$POSTGRES_PASSWORD psql $psql_url -c "
        SELECT version();
    "
}

# Function to cleanup containers
cleanup() {
    print_status "Cleaning up existing containers..."
    docker rm -f $CONTAINER_NAME_PG15 2>/dev/null || true
    docker rm -f $CONTAINER_NAME_PG16 2>/dev/null || true
}

# Function to create tenant via Supavisor API
create_tenant() {
    print_status "Creating ${TENANT_NAME} tenant via Supavisor API..."

    local response=$(curl -s -w "%{http_code}" -X PUT \
      "${POOLER_API}/api/tenants/${TENANT_NAME}" \
      --header 'Accept: application/json' \
      --header "Authorization: Bearer ${BEARER_TOKEN}" \
      --header 'Content-Type: application/json' \
      --data-raw '{
      "tenant": {
        "db_host": "'${DB_HOST}'",
        "db_port": '${POSTGRES_PORT}',
        "db_database": "'${POSTGRES_DB}'",
        "ip_version": "auto",
        "enforce_ssl": false,
        "require_user": false,
        "auth_query": "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1;",
        "users": [
          {
            "db_user": "'${POSTGRES_USER}'",
            "db_password": "'${POSTGRES_PASSWORD}'",
            "pool_size": 20,
            "mode_type": "transaction",
            "is_manager": true
          }
        ]
      }
    }')

    local http_code="${response: -3}"
    local body="${response%???}"

    if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 201 ]; then
        print_status "${TENANT_NAME} tenant created successfully"
    else
        print_warning "Failed to create ${TENANT_NAME} tenant (HTTP $http_code). This might be normal if Supavisor is not running."
        print_warning "Response: $body"
        print_warning "Continuing with tests anyway..."
    fi
}

# Function to terminate tenant via Supavisor API
terminate_tenant() {
    print_status "Terminating ${TENANT_NAME} tenant (clearing cache)..."

    local response=$(curl -s -w "%{http_code}" -X GET \
      "${POOLER_API}/api/tenants/${TENANT_NAME}/terminate" \
      --header 'Accept: application/json' \
      --header "Authorization: Bearer ${BEARER_TOKEN}")

    local http_code="${response: -3}"
    local body="${response%???}"

    if [ "$http_code" -eq 200 ]; then
        print_status "${TENANT_NAME} tenant terminated successfully"
    else
        print_warning "Failed to terminate ${TENANT_NAME} tenant (HTTP $http_code). This might be normal if Supavisor is not running."
        print_warning "Response: $body"
        print_warning "Continuing with tests anyway..."
    fi
}

# Function to start PostgreSQL container
start_postgres() {
    local version=$1
    local container_name=$2

    print_status "Starting PostgreSQL $version container..."

    docker run -d \
        --name $container_name \
        -e POSTGRES_USER=$POSTGRES_USER \
        -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
        -e POSTGRES_DB=$POSTGRES_DB \
        -p $POSTGRES_PORT:5432 \
        postgres:$version

    wait_for_postgres $container_name
}

# Function to test PostgreSQL 15
test_postgres_15() {
    local should_create_tenant=${1:-true}

    print_status "=== Testing PostgreSQL 15 ==="

    # Step 1: Start PostgreSQL 15
    print_status "=== Step 1: Starting PostgreSQL 15 ==="
    start_postgres 15 $CONTAINER_NAME_PG15

    # Step 2: Create tenant (after database is running)
    if [ "$should_create_tenant" = true ]; then
        create_tenant
        sleep 2
    fi

    # Step 3: Run test queries on PostgreSQL 15
    print_status "=== Step 3: Testing PostgreSQL 15 (Direct Connection) ==="
    run_test_query $CONTAINER_NAME_PG15 "15" false

    print_status "=== Step 3b: Testing PostgreSQL 15 (Via Pooler) ==="
    run_test_query $CONTAINER_NAME_PG15 "15" true

    # Step 4: Stop PostgreSQL 15 container
    print_status "=== Step 4: Stopping PostgreSQL 15 ==="
    docker stop $CONTAINER_NAME_PG15
    docker rm $CONTAINER_NAME_PG15
    print_status "PostgreSQL 15 container stopped and removed"
}

# Function to test PostgreSQL 16
test_postgres_16() {
    local should_create_tenant=${1:-true}

    print_status "=== Testing PostgreSQL 16 ==="

    # Step 1: Start PostgreSQL 16
    print_status "=== Step 1: Starting PostgreSQL 16 ==="
    start_postgres 16 $CONTAINER_NAME_PG16

    # Step 2: Create tenant (after database is running)
    if [ "$should_create_tenant" = true ]; then
        create_tenant
        sleep 2
    fi

    # Step 3: Run test queries on PostgreSQL 16
    print_status "=== Step 3: Testing PostgreSQL 16 (Direct Connection) ==="
    run_test_query $CONTAINER_NAME_PG16 "16" false

    print_status "=== Step 3b: Testing PostgreSQL 16 (Via Pooler) ==="
    run_test_query $CONTAINER_NAME_PG16 "16" true

    print_status "=== Test completed successfully! ==="
    print_warning "PostgreSQL 16 container is still running. Use 'docker stop $CONTAINER_NAME_PG16' to stop it."
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [VERSION]"
    echo ""
    echo "OPTIONS:"
    echo "  VERSION    PostgreSQL version to test (15 or 16)"
    echo "             If not specified, tests both versions with upgrade scenario"
    echo ""
    echo "EXAMPLES:"
    echo "  $0         # Test both versions (15 -> 16 upgrade scenario)"
    echo "  $0 15      # Test only PostgreSQL 15"
    echo "  $0 16      # Test only PostgreSQL 16"
}

# Main execution
main() {
    local version_arg=$1

    # Handle help flag
    if [ "$version_arg" = "-h" ] || [ "$version_arg" = "--help" ]; then
        show_usage
        exit 0
    fi

    # Validate version argument if provided
    if [ -n "$version_arg" ] && [ "$version_arg" != "15" ] && [ "$version_arg" != "16" ]; then
        print_error "Invalid version: $version_arg. Supported versions: 15, 16"
        show_usage
        exit 1
    fi

    print_status "Starting PostgreSQL test scenario..."

    # Cleanup any existing containers
    cleanup

    case "$version_arg" in
        "15")
            test_postgres_15 true
            ;;
        "16")
            test_postgres_16 true
            ;;
        "")
            print_status "Testing full upgrade scenario: PostgreSQL 15 -> 16"
            test_postgres_15 true

            # Terminate tenant to clear cache before upgrade
            terminate_tenant

            # Wait a moment to ensure port is released
            sleep 2

            test_postgres_16 false
            ;;
    esac
}

# Trap to cleanup on script exit
trap cleanup EXIT

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if psql is available on the host
if ! command -v psql >/dev/null 2>&1; then
    print_error "psql is not available on the host system. Please install PostgreSQL client tools."
    print_error "On macOS: brew install postgresql"
    print_error "On Ubuntu/Debian: sudo apt-get install postgresql-client"
    print_error "On CentOS/RHEL: sudo yum install postgresql"
    exit 1
fi

# Check if pg_isready is available on the host
if ! command -v pg_isready >/dev/null 2>&1; then
    print_error "pg_isready is not available on the host system. Please install PostgreSQL client tools."
    exit 1
fi

print_status "Starting test scenario..."

# Run main function with command line arguments
main "$1"
