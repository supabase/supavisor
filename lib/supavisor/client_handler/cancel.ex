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

  @pre_claim_timeout 5_000
  @post_grant_timeout 15_000

  @doc """
  Called upon receiving cancel requests, broadcasts to relevant client handler and waits for acknowledgment
  before closing the cancel connection.
  """
  @spec send_cancel_query(non_neg_integer, non_neg_integer, term) :: :ok | {:error, term}
  def send_cancel_query(pid, key, msg \\ :cancel_query)

  def send_cancel_query(pid, key, :cancel_query) do
    ref = make_ref()

    PubSub.broadcast(
      Supavisor.PubSub,
      "cancel_req:#{pid}_#{key}",
      {:cancel_query, self(), ref}
    )

    wait_for_claim(ref)
  end

  def send_cancel_query(pid, key, msg) do
    PubSub.broadcast(
      Supavisor.PubSub,
      "cancel_req:#{pid}_#{key}",
      msg
    )
  end

  defp wait_for_claim(ref) do
    receive do
      {:cancel_claim, owner_pid, ^ref} ->
        mref = Process.monitor(owner_pid)
        send(owner_pid, {:cancel_granted, ref})
        wait_for_ack(ref, owner_pid, mref)

      {:cancel_ack, ^ref} ->
        :ok
    after
      @pre_claim_timeout -> :ok
    end
  end

  defp wait_for_ack(ref, owner_pid, mref) do
    receive do
      {:cancel_ack, ^ref} ->
        Process.demonitor(mref, [:flush])
        :ok

      {:DOWN, ^mref, :process, ^owner_pid, _reason} ->
        :ok
    after
      @post_grant_timeout ->
        Process.demonitor(mref, [:flush])
        :ok
    end
  end

  @doc """
  Called by ClientHandlers when starting a connection
  """
  @spec listen_cancel_query(non_neg_integer, non_neg_integer) :: :ok | {:errr, term}
  def listen_cancel_query(pid, key) do
    PubSub.subscribe(Supavisor.PubSub, "cancel_req:#{pid}_#{key}")
  end
end
