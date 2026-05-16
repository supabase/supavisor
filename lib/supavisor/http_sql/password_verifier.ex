defmodule Supavisor.HttpSql.PasswordVerifier do
  @moduledoc """
  Synchronously verifies a Postgres password against the SCRAM-SHA-256
  secrets cached for a `(tenant, user)` pair. No round-trip to Postgres —
  the check runs entirely on the local node from the cached
  `Supavisor.ClientAuthentication.ValidationSecrets`.

  This is the **only** reliable place to detect bad-password attempts on
  the HTTP /sql path. Once the password is forwarded to the Postgrex
  pool, an auth failure is buried beneath connect-retry loops, queue
  timeouts, and `DBConnection.ConnectionError` wrapping — making
  brute-force counters unreliable. By verifying upfront we:

    1. Reject bad passwords with a clean 401 before any pool churn.
    2. Record the failure against the **real HTTP caller IP** so the
       per-`(tenant, ip)` CircuitBreaker bucket reflects who is
       attacking us, not our loopback peer.

  The SCRAM verification mirrors what a Postgres server does in its
  SASL-server role:

      salted_password = Hi(saslprep(password), salt, iterations)
      client_key      = HMAC(salted_password, "Client Key")
      stored_key      = H(client_key)

  We re-compute `stored_key` from the supplied plaintext and compare it
  against the cached `SASLSecrets.stored_key`. Equal → password OK.
  """

  alias Supavisor.ClientAuthentication
  alias Supavisor.Secrets.SASLSecrets

  @type result :: :ok | {:error, :invalid_password} | {:error, :no_secrets | term()}

  @doc """
  Verify `password` against the cached SASL secrets for `(tenant, user)`.

  Returns `:ok` on match, `{:error, :invalid_password}` on mismatch, or
  `{:error, reason}` if validation secrets are unavailable (e.g.
  auth_query path with upstream Postgres unreachable). The caller MUST
  treat `{:error, _}` as an authentication failure and record a
  CircuitBreaker tick.
  """
  @spec verify(Supavisor.Tenants.Tenant.t(), Supavisor.Tenants.User.t(), String.t()) :: result
  def verify(tenant, user, password) when is_binary(password) do
    case fetch_secrets(tenant, user) do
      {:ok, %SASLSecrets{} = secrets} -> check_password(secrets, password)
      {:error, _} = err -> err
    end
  end

  # ---------------------------------------------------------------------------

  defp fetch_secrets(tenant, user) do
    # `Supavisor.id` is the cache identity used by ClientAuthentication.
    # Mode/db here don't affect the validation-secret lookup; we use
    # transaction-mode for parity with how HTTP /sql connects.
    require Supavisor

    id =
      Supavisor.id(
        type: :single,
        tenant: tenant.external_id,
        user: user.db_user,
        mode: :transaction,
        db: tenant.db_database || "postgres"
      )

    case ClientAuthentication.fetch_validation_secrets(id, tenant, user) do
      {:ok, %{sasl_secrets: %SASLSecrets{} = sasl}} -> {:ok, sasl}
      {:ok, _} -> {:error, :no_secrets}
      {:error, _} = err -> err
    end
  end

  defp check_password(%SASLSecrets{} = s, password) do
    salted_password =
      :pgo_scram.hi(:pgo_sasl_prep_profile.validate([password]), s.salt, s.iterations)

    client_key = :pgo_scram.hmac(salted_password, "Client Key")
    derived_stored_key = :pgo_scram.h(client_key)

    if constant_time_equal?(derived_stored_key, s.stored_key) do
      :ok
    else
      {:error, :invalid_password}
    end
  end

  # Constant-time binary comparison to avoid timing side-channels in the
  # password check.
  defp constant_time_equal?(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp constant_time_equal?(_, _), do: false
end
