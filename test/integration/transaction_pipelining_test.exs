defmodule Supavisor.Integration.TransactionPipeliningTest do
  use Supavisor.DataCase, async: false

  alias Supavisor.Support.ProtocolClient

  @moduletag :integration

  @tenants ["proxy_tenant_ps_disabled", "proxy_tenant_ps_enabled"]

  for tenant <- @tenants do
    test "delivers every reply in a pipelined batch (#{tenant})" do
      sock = connect(unquote(tenant))
      n = 50

      # Fire N simple queries in a single write so they pipeline.
      :ok = :gen_tcp.send(sock, pipeline(n))

      assert recv_ready_for_queries(sock, n) == n
    end

    test "releases and reuses the backend after a pipelined batch (#{tenant})" do
      sock = connect(unquote(tenant))

      :ok = :gen_tcp.send(sock, pipeline(5))
      assert recv_ready_for_queries(sock, 5) == 5

      # A fresh query on the same client connection must still succeed.
      :ok = :gen_tcp.send(sock, :pgo_protocol.encode_query_message("SELECT 1"))
      assert recv_ready_for_queries(sock, 1) == 1
    end
  end

  defp connect(tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)

    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    ProtocolClient.authenticate(sock, "#{db_conf[:username]}.#{tenant}", db_conf[:password])
    sock
  end

  # N simple queries as one iolist, so a single send pipelines them.
  defp pipeline(n) do
    Enum.map(1..n, fn i -> :pgo_protocol.encode_query_message("SELECT #{i}") end)
  end

  # Reads until `n` ReadyForQuery packets have been seen, returning the count.
  defp recv_ready_for_queries(sock, n, buf \\ <<>>) do
    {pkts, _rest} = Supavisor.Protocol.split_pkts(buf)
    count = Enum.count(pkts, &match?(<<?Z, _::binary>>, &1))

    if count >= n do
      count
    else
      case :gen_tcp.recv(sock, 0, 5000) do
        {:ok, more} ->
          recv_ready_for_queries(sock, n, buf <> more)

        {:error, reason} ->
          flunk("received only #{count}/#{n} ReadyForQuery before #{inspect(reason)}")
      end
    end
  end
end
