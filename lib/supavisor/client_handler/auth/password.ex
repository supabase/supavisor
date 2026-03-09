defmodule Supavisor.ClientHandler.Auth.Password do
  @moduledoc """
  Handles cleartext password authentication between the client and Supavisor.

  The client sends a plaintext password over an SSL connection. Depending on the
  tenant configuration:

    - `require_user: true` — the password is validated against the user's password
      stored in Supavisor's own database.
    - `require_user: false` — the password is validated against SCRAM secrets fetched
      from the upstream database via auth_query.

  The flow is:

    1. `new_context/2` — builds the initial auth context from tenant info and pool id.
    2. `handle_password/2` — parses the client's password message, validates it, and
       returns the resolved upstream secrets.
  """

  defmodule Context do
    @moduledoc """
    Holds state for the cleartext password authentication exchange.

    Fields:
      - `id` — the pool identifier tuple
      - `tenant` — the tenant record
      - `user` — the user record from Supavisor's database
      - `db_user` — the username of the authenticating client
    """

    @type t :: %__MODULE__{
            id: Supavisor.id(),
            tenant: map(),
            user: map(),
            db_user: String.t()
          }

    defstruct [:id, :tenant, :user, :db_user]
  end

  alias Supavisor.ClientHandler.Auth.{PasswordSecrets, ValidationSecrets}
  alias Supavisor.Protocol.Server

  require Supavisor

  @doc """
  Creates a new auth context from tenant info and pool id.
  """
  @spec new_context(map(), Supavisor.id()) :: Context.t()
  def new_context(info, id) do
    Supavisor.id(user: db_user) = id

    %Context{id: id, tenant: info.tenant, user: info.user, db_user: db_user}
  end

  def get_user_and_db_user(%Context{user: user, db_user: db_user}), do: {user, db_user}

  @doc """
  Processes the client's cleartext password message.

  When `require_user` is true, validates the password against the user's
  password stored in Supavisor's own database and returns `PasswordSecrets`.

  When `require_user` is false, fetches SCRAM validation secrets via auth_query,
  and verifies the password against the stored key.
  """
  @spec handle_password(Context.t(), binary()) ::
          {:ok, PasswordSecrets.t()} | {:error, Exception.t()}
  def handle_password(context, bin) do
    with {:ok, password} <- decode_password(bin, context),
         :ok <- validate_password(password, context) do
      {:ok, %PasswordSecrets{user: context.db_user, password: password}}
    end
  end

  defp validate_password(password, %{tenant: %{require_user: true}} = context) do
    if password == context.user.db_password do
      :ok
    else
      {:error, %Supavisor.Errors.WrongPasswordError{user: context.db_user}}
    end
  end

  defp validate_password(password, ctx) do
    with {:ok, %{password_secrets: password_secrets, sasl_secrets: sasl_secrets}} <-
           ValidationSecrets.fetch_validation_secrets(ctx.id, ctx.tenant, ctx.user, ctx.db_user) do
      if password_secrets && password == password_secrets.password do
        :ok
      else
        salt = Base.decode64!(sasl_secrets.salt)

        salted_password =
          :pgo_scram.hi(
            :pgo_sasl_prep_profile.validate(password),
            salt,
            sasl_secrets.iterations
          )

        client_key = :pgo_scram.hmac(salted_password, "Client Key")
        computed_stored_key = :pgo_scram.h(client_key)

        if computed_stored_key == sasl_secrets.stored_key do
          :ok
        else
          {:error, %Supavisor.Errors.WrongPasswordError{user: ctx.db_user}}
        end
      end
    end
  end

  @spec decode_password(binary(), Context.t()) ::
          {:ok, binary()} | {:error, Exception.t()}
  defp decode_password(bin, context) do
    case Server.decode_pkt(bin) do
      {:ok, %{tag: :password_message, payload: {:cleartext_password, password}}, _} ->
        {:ok, IO.iodata_to_binary(password)}

      {:ok, other, _} ->
        {:error,
         %Supavisor.Errors.AuthProtocolError{
           details: {:unexpected_message, other},
           context: context
         }}

      {:error, error} ->
        {:error,
         %Supavisor.Errors.AuthProtocolError{
           details: {:decode_error, error},
           context: context
         }}
    end
  end
end
