defmodule Supavisor.ClientHandler.Cancel do
  @moduledoc """
  Helpers for dealing with query canceling.

  From the docs:

  > To issue a cancel request, the frontend opens a new connection to the server and sends a CancelRequest message,
  > rather than the StartupMessage message that would ordinarily be sent across a new connection. The server
  > will process this request and then close the connection. For security reasons, no direct reply is made to the
  > cancel request message.

  Cancel requests are sent through Phoenix PubSub. ClientHandlers listen to their key and other client
  handlers may send cancel requests on it.
  """

  require Logger
  alias Phoenix.PubSub
  alias Supavisor.HandlerHelpers
  require Supavisor.Protocol.Server, as: Server

  # Bounds the cancel connection's wait for the ack, which never comes for a session that already ended,
  # so keep it short, but longer than @upstream_timeout so a slow database still gets its ack.
  @cancel_timeout 2_000
  # The owning handler waits inline for Postgres to close the cancel socket, at most this long.
  @upstream_timeout 1_000

  @doc """
  Called upon receiving cancel requests, broadcasts to relevant client handler
  """
  @spec send_cancel_query(non_neg_integer, non_neg_integer, term) :: :ok | {:errr, term}
  def send_cancel_query(pid, key, msg \\ :cancel_query) do
    PubSub.broadcast(
      Supavisor.PubSub,
      "cancel_req:#{pid}_#{key}",
      msg
    )
  end

  @doc """
  Broadcasts a cancel request and waits until the owning client handler has forwarded it to the database.

  Clients may send their next query as soon as the cancel connection closes, so it must not close earlier.
  Gives up after `timeout` (no handler owns the key, or one running an older version that never replies).
  The ack is per session, so a second cancel sent while the first is being forwarded may be released by the first's ack.
  """
  @spec send_cancel_query_and_wait(non_neg_integer, non_neg_integer, timeout) ::
          :ok | {:error, :timeout}
  def send_cancel_query_and_wait(pid, key, timeout \\ @cancel_timeout) do
    topic = "cancel_done:#{pid}_#{key}"
    :ok = PubSub.subscribe(Supavisor.PubSub, topic)
    :ok = send_cancel_query(pid, key)

    result =
      receive do
        :cancel_done -> :ok
      after
        timeout -> {:error, :timeout}
      end

    :ok = PubSub.unsubscribe(Supavisor.PubSub, topic)
    result
  end

  @doc """
  Tells the cancel connections waiting on `{pid, key}` that the cancel reached the database
  """
  @spec reply_cancel_done({non_neg_integer, non_neg_integer} | nil) :: :ok | {:error, term}
  def reply_cancel_done({pid, key}) do
    PubSub.broadcast(Supavisor.PubSub, "cancel_done:#{pid}_#{key}", :cancel_done)
  end

  def reply_cancel_done(nil), do: :ok

  @doc """
  Called by ClientHandlers when starting a connection
  """
  @spec listen_cancel_query(non_neg_integer, non_neg_integer) :: :ok | {:errr, term}
  def listen_cancel_query(pid, key) do
    PubSub.subscribe(Supavisor.PubSub, "cancel_req:#{pid}_#{key}")
  end

  @doc """
  If there's an ongoing query, forward the message to cancel it to the checked out connection

  Called by the client handler when receiving a cancel requests
  """
  def maybe_forward_cancel_to_db(:busy, data) do
    key = {data.tenant, data.db_connection}
    Logger.debug("ClientHandler: Cancel query for #{inspect(key)}")
    {_pool, db_pid, _db_sock} = data.db_connection

    case db_pid_meta(key) do
      [{^db_pid, meta}] ->
        msg = Server.cancel_message(meta.pid, meta.key)
        opts = [:binary, {:packet, :raw}, {:active, false}, meta.ip_version]
        {:ok, sock} = :gen_tcp.connect(meta.host, meta.port, opts)
        :ok = HandlerHelpers.sock_send({:gen_tcp, sock}, msg)
        # Postgres closes the cancel connection only after it has signalled the backend
        _ = :gen_tcp.recv(sock, 0, @upstream_timeout)
        :ok = HandlerHelpers.sock_close({:gen_tcp, sock})

      error ->
        Logger.error(
          "ClientHandler: Received cancel but no proc was found #{inspect(key)} #{inspect(error)}"
        )
    end
  end

  def maybe_forward_cancel_to_db(_state, _data) do
    :ok
  end

  defp db_pid_meta({_, {_, pid, _}} = _key) do
    rkey = Supavisor.Registry.PoolPids

    pid
    |> node()
    |> :erpc.call(Registry, :lookup, [rkey, pid], 15_000)
  end
end
