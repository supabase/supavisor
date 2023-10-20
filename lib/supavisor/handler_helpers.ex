defmodule Supavisor.HandlerHelpers do
  @moduledoc false

  alias Supavisor, as: S
  alias Supavisor.Protocol.Server

  @spec sock_send(S.sock(), iodata()) :: :ok | {:error, term()}
  def sock_send({mod, sock}, data) do
    mod.send(sock, data)
  end

  @spec setopts(S.sock(), term()) :: :ok | {:error, term()}
  def setopts({mod, sock}, opts) do
    mod = if mod == :gen_tcp, do: :inet, else: mod
    mod.setopts(sock, opts)
  end

  @spec activate(S.sock()) :: :ok | {:error, term}
  def activate({:gen_tcp, sock}) do
    :inet.setopts(sock, active: true)
  end

  def activate({:ssl, sock}) do
    :ssl.setopts(sock, active: true)
  end

  @spec try_ssl_handshake(S.tcp_sock(), boolean) ::
          {:ok, S.sock()} | {:error, term()}
  def try_ssl_handshake(sock, true) do
    case sock_send(sock, Server.ssl_request()) do
      :ok -> ssl_recv(sock)
      error -> error
    end
  end

  def try_ssl_handshake(sock, false), do: {:ok, sock}

  @spec ssl_recv(S.tcp_sock()) :: {:ok, S.ssl_sock()} | {:error, term}
  def ssl_recv({:gen_tcp, sock} = s) do
    case :gen_tcp.recv(sock, 1, 15_000) do
      {:ok, <<?S>>} -> ssl_connect(s)
      {:ok, <<?N>>} -> {:ok, s}
      {:error, _} = error -> error
    end
  end

  @spec ssl_connect(S.tcp_sock(), pos_integer) ::
          {:ok, S.ssl_sock()} | {:error, term}
  def ssl_connect({:gen_tcp, sock}, timeout \\ 5000) do
    opts = [verify: :verify_none]

    case :ssl.connect(sock, opts, timeout) do
      {:ok, ssl_sock} -> {:ok, {:ssl, ssl_sock}}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec send_error(S.sock(), String.t(), String.t()) :: :ok | {:error, term()}
  def send_error(sock, code, message) do
    data = Server.error_message(code, message)
    sock_send(sock, data)
  end

  @spec try_get_sni(S.sock()) :: String.t() | nil
  def try_get_sni({:ssl, sock}) do
    case :ssl.connection_information(sock, [:sni_hostname]) do
      {:ok, [sni_hostname: sni]} -> List.to_string(sni)
      _ -> nil
    end
  end

  def try_get_sni(_), do: nil

  @spec parse_user_info(map) :: {String.t() | nil, String.t()}
  def parse_user_info(%{"user" => user, "options" => %{"reference" => ref}}) do
    {user, ref}
  end

  def parse_user_info(%{"user" => user}) do
    case :binary.matches(user, ".") do
      [] ->
        {user, nil}

      matches ->
        {pos, 1} = List.last(matches)
        <<name::size(pos)-binary, ?., external_id::binary>> = user
        {name, external_id}
    end
  end
end
