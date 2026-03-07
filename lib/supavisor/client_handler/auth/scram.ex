defmodule Supavisor.ClientHandler.Auth.SCRAM do
  @moduledoc """
  Handles SCRAM-SHA-256 authentication between the client and Supavisor.

  Implements the server side of the SCRAM exchange as defined in RFC 5802.
  The flow is:

    1. `new_context/2` — builds the initial auth context from tenant info and pool id.
    2. `handle_scram_first/2` — processes the client's first message, fetches validation
       secrets, computes signatures, and returns the server's first message.
    3. `handle_scram_final/2` — processes the client's final message, verifies the SCRAM
       proof, and returns the server's final message along with the resolved upstream secrets.
  """

  defmodule Context do
    @moduledoc """
    Holds state across the SCRAM authentication exchange.

    Fields:
      - `id` — the pool identifier tuple
      - `tenant` — the tenant record
      - `manager_user` — the manager user record (used for auth_query lookups)
      - `user` — the username of the authenticating client
      - `nonce` — the client nonce from the first SCRAM message
      - `channel` — the channel binding value from the first SCRAM message
      - `signatures` — computed client and server signatures (`%{client: binary, server: binary}`)
      - `secret` — the `SASLSecrets` struct used for validation
    """

    # TODO: rename `manager_user` to `user`. If `require_user` is `true`, it is the `user` with name == db_user,
    # not the manager user.
    @type t :: %__MODULE__{
            id: Supavisor.id(),
            tenant: map(),
            manager_user: map(),
            user: String.t(),
            nonce: binary() | nil,
            channel: binary() | nil,
            signatures: %{client: binary(), server: binary()} | nil,
            secret: Supavisor.ClientHandler.Auth.SASLSecrets.t() | nil
          }

    defstruct [:id, :tenant, :signatures, :manager_user, :nonce, :channel, :secret, :user]
  end

  alias Supavisor.ClientHandler.Auth.{SASLSecrets, ValidationSecrets}
  alias Supavisor.Protocol.Server
  alias Supavisor.Helpers

  @doc """
  Creates a new SCRAM auth context from tenant info and pool id.
  """
  @spec new_context(map(), Supavisor.id()) :: Context.t()
  def new_context(info, id) do
    {{_, _}, user, _mode, _database, _search_path} = id

    %Context{id: id, tenant: info.tenant, manager_user: info.user, user: user}
  end

  def get_user_and_db_user(%Context{manager_user: user, user: db_user}), do: {user, db_user}

  @doc """
  Processes the client's SCRAM first message.

  Decodes the message, validates the username, fetches validation secrets,
  and computes the SCRAM signatures. Returns the server's first message
  and an updated context with the signatures and secret populated.
  """
  @spec handle_scram_first(Context.t(), binary()) ::
          {:ok, binary(), Context.t()} | {:error, Exception.t()}
  def handle_scram_first(context, bin) do
    with {:ok, {user, nonce, channel}} <- decode_scram_first(bin, context),
         {:ok, _} <- validate_scram_user(context, user),
         {:ok, %{sasl_secrets: secret}} <-
           ValidationSecrets.fetch_validation_secrets(
             context.id,
             context.tenant,
             context.manager_user,
             context.user
           ) do
      message = Server.exchange_first_message(nonce, secret.salt)
      server_first_parts = Helpers.parse_server_first(message, nonce)

      signatures =
        Helpers.signatures(
          secret.stored_key,
          secret.server_key,
          server_first_parts,
          nonce,
          user,
          channel
        )

      new_context = %Context{
        context
        | signatures: signatures,
          secret: secret,
          nonce: nonce,
          channel: channel
      }

      {:ok, message, new_context}
    end
  end

  @doc """
  Processes the client's SCRAM final message.

  Verifies the client proof against the stored key. On success, returns the
  server's final message and the resolved `SASLSecrets` (with `client_key` populated).
  """
  @spec handle_scram_final(Context.t(), binary()) ::
          {:ok, iodata(), SASLSecrets.t()} | {:error, Exception.t()}
  def handle_scram_final(%Context{signatures: %{server: server_signature}} = context, bin) do
    with {:ok, {:first_msg_response, %{"p" => p}}} <-
           decode_password_message(:first_msg_response, bin, context),
         {:ok, client_key} <- validate_scram_proof(context, p) do
      message = Server.exchange_message(:final, "v=#{Base.encode64(server_signature)}")
      final_secrets = %{context.secret | client_key: client_key}
      {:ok, message, final_secrets}
    end
  end

  @spec validate_scram_proof(Context.t(), binary()) ::
          {:ok, binary()} | {:error, Exception.t()}
  defp validate_scram_proof(context, client_proof) do
    client_key = :crypto.exor(Base.decode64!(client_proof), context.signatures.client)

    if Helpers.hash(client_key) == context.secret.stored_key do
      {:ok, client_key}
    else
      {:error, %Supavisor.Errors.WrongPasswordError{user: context.user}}
    end
  end

  @spec decode_scram_first(binary(), Context.t()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, Exception.t()}
  defp decode_scram_first(bin, context) do
    with {:ok, {:scram_sha_256, %{"n" => user, "r" => nonce, "c" => channel}}} <-
           decode_password_message(:scram_sha_256, bin, context) do
      {:ok, {user, nonce, channel}}
    end
  end

  @spec decode_password_message(atom(), binary(), Context.t()) ::
          {:ok, term()} | {:error, Exception.t()}
  defp decode_password_message(expected_type, bin, context) do
    case Server.decode_pkt(bin) do
      {:ok, %{tag: :password_message, payload: {^expected_type, _} = payload}, _} ->
        {:ok, payload}

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

  @spec validate_scram_user(Context.t(), binary()) ::
          {:ok, binary()} | {:error, Exception.t()}
  defp validate_scram_user(context, user) do
    if user not in [context.user, ""] do
      # TODO: proper auth error here
      {:error, %Supavisor.Errors.AuthProtocolError{}}
    else
      {:ok, user}
    end
  end
end
