defmodule Supavisor.HttpSql.Wire do
  @moduledoc """
  Builders for PostgreSQL frontend wire-protocol messages used by the HTTP /sql
  client handler. All messages return iodata so they can be passed straight to
  `Supavisor.HandlerHelpers.sock_send/2`.

  Bind is hard-wired to text format for every parameter and every result column,
  which is what the Neon driver expects and what lets us avoid binary type
  encoders for HTTP requests.

  The PostgreSQL wire format spec lives in
  https://www.postgresql.org/docs/current/protocol-message-formats.html.
  """

  @typedoc "A parameter value: a UTF-8 encoded text representation, or nil for SQL NULL."
  @type param :: binary() | nil

  @doc """
  Parse message ('P'). `name` is the prepared-statement name — pass `""` for the
  unnamed statement (the only mode the HTTP path uses).

  The trailing parameter-type-OID array is sent empty (Int16 0), letting the
  backend infer types from the parsed query. This is intentional: the HTTP
  handler reads `ParameterDescription` later, before sending Bind.
  """
  @spec parse(binary(), binary()) :: iodata()
  def parse(name, sql) when is_binary(name) and is_binary(sql) do
    payload = [name, 0, sql, 0, <<0::16>>]
    [?P, len(payload), payload]
  end

  @doc """
  Bind message ('B'). All parameters are sent in text format; all result columns
  are requested in text format.

  Per the protocol, a `parameter format code count` of 0 means every parameter
  uses the default (text) format. The same convention is used for the result
  column format codes.
  """
  @spec bind(binary(), binary(), [param()]) :: iodata()
  def bind(portal, statement, params)
      when is_binary(portal) and is_binary(statement) and is_list(params) do
    encoded_params = Enum.map(params, &encode_param/1)

    payload = [
      portal,
      0,
      statement,
      0,
      # parameter format code count = 0 -> all text
      <<0::16>>,
      # parameter count
      <<length(params)::16>>,
      encoded_params,
      # result column format code count = 0 -> all text
      <<0::16>>
    ]

    [?B, len(payload), payload]
  end

  @doc """
  Describe message ('D'). `kind` is `:statement` (`'S'`) for a prepared
  statement or `:portal` (`'P'`) for a portal.
  """
  @spec describe(:statement | :portal, binary()) :: iodata()
  def describe(kind, name) when kind in [:statement, :portal] and is_binary(name) do
    indicator =
      case kind do
        :statement -> ?S
        :portal -> ?P
      end

    payload = [indicator, name, 0]
    [?D, len(payload), payload]
  end

  @doc """
  Execute message ('E'). `row_limit` of 0 means \"return all rows\".
  """
  @spec execute(binary(), non_neg_integer()) :: iodata()
  def execute(portal, row_limit \\ 0)
      when is_binary(portal) and is_integer(row_limit) and row_limit >= 0 do
    payload = [portal, 0, <<row_limit::32>>]
    [?E, len(payload), payload]
  end

  @doc """
  Sync message ('S'). No payload.
  """
  @spec sync() :: iodata()
  def sync, do: [?S, <<4::32>>]

  @doc """
  Close message ('C'). `kind` is `:statement` (`'S'`) or `:portal` (`'P'`).
  """
  @spec close(:statement | :portal, binary()) :: iodata()
  def close(kind, name) when kind in [:statement, :portal] and is_binary(name) do
    indicator =
      case kind do
        :statement -> ?S
        :portal -> ?P
      end

    payload = [indicator, name, 0]
    [?C, len(payload), payload]
  end

  @doc """
  Simple query message ('Q'). Used for transaction-control statements
  (BEGIN/COMMIT/ROLLBACK/SET TRANSACTION) where parameter binding is irrelevant.
  """
  @spec query(binary()) :: iodata()
  def query(sql) when is_binary(sql) do
    payload = [sql, 0]
    [?Q, len(payload), payload]
  end

  # ---------------------------------------------------------------------------

  defp encode_param(nil), do: <<-1::32-signed>>

  defp encode_param(bin) when is_binary(bin) do
    [<<byte_size(bin)::32-signed>>, bin]
  end

  # Length is the 4-byte length field plus the payload size, but excludes the
  # 1-byte message type tag.
  defp len(payload), do: <<IO.iodata_length(payload) + 4::32>>
end
