defmodule Supavisor.Support.ProtocolClient do
  @moduledoc """
  Minimal raw-socket Postgres wire protocol helpers, for tests that need a
  real proxied connection without going through Postgrex/pgo.

  A socket is a `:gen_tcp` socket, or `{:ssl, socket}` for TLS.
  """

  @doc """
  Performs the SCRAM-SHA-256 handshake on `sock` and reads until
  ReadyForQuery. `sock` must already be connected, in passive mode.
  """
  def authenticate(sock, user, password) do
    startup = :pgo_protocol.encode_startup_message([{"user", user}])
    :ok = sock_send(sock, startup)

    {:ok, <<?R, _::32, 10::32, _methods_bin::binary>>} = sock_recv(sock, 5000)

    nonce = :pgo_scram.get_nonce(16)
    client_first = :pgo_scram.get_client_first(user, nonce)
    client_first_size = :erlang.iolist_size(client_first)
    sasl_initial = ["SCRAM-SHA-256", 0, <<client_first_size::32>>, client_first]
    :ok = sock_send(sock, :pgo_protocol.encode_scram_response_message(sasl_initial))

    {:ok, <<?R, _::32, 11::32, server_first::binary>>} = sock_recv(sock, 5000)
    server_first_parts = :pgo_scram.parse_server_first(server_first, nonce)

    {client_final, server_proof} =
      :pgo_scram.get_client_final(server_first_parts, nonce, user, password)

    :ok = sock_send(sock, :pgo_protocol.encode_scram_response_message(client_final))

    {:ok, auth_data} = sock_recv(sock, 5000)
    recv_until_ready_for_query(sock, auth_data)

    server_proof
  end

  @doc """
  Reads from `sock` until a ReadyForQuery packet is seen in the accumulated
  buffer, starting from an already-received `buf`.
  """
  def recv_until_ready_for_query(sock, buf) do
    case Supavisor.Protocol.split_pkts(buf) do
      {pkts, ""} ->
        if Enum.any?(pkts, &match?(<<?Z, _::binary>>, &1)) do
          :ok
        else
          {:ok, more} = sock_recv(sock, 5000)
          recv_until_ready_for_query(sock, more)
        end

      _ ->
        {:ok, more} = sock_recv(sock, 5000)
        recv_until_ready_for_query(sock, buf <> more)
    end
  end

  def sock_send({:ssl, sock}, data), do: :ssl.send(sock, data)
  def sock_send(sock, data), do: :gen_tcp.send(sock, data)

  def sock_recv({:ssl, sock}, timeout), do: :ssl.recv(sock, 0, timeout)
  def sock_recv(sock, timeout), do: :gen_tcp.recv(sock, 0, timeout)
end
