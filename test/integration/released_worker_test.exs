defmodule Supavisor.Integration.ReleasedWorkerTest do
  # A released worker must be back in the pool before its client's next query asks for one.
  # The ClientHandler blocks in poolboy's checkout for that query, and with one worker that
  # is the worker being returned: a return that depended on anything the ClientHandler does
  # afterwards would wait out the whole checkout timeout on an idle pool.
  use Supavisor.DataCase, async: false

  require Supavisor

  alias Supavisor.Support.ProtocolClient

  @moduletag :integration

  @queries 3_000
  @checkout_timeout 1_000

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "released_worker_#{System.unique_integer([:positive])}"

    {:ok, _} =
      Supavisor.Tenants.create_tenant(%{
        db_host: db_conf[:hostname],
        db_port: db_conf[:port],
        db_database: db_conf[:database],
        default_parameter_status: %{},
        external_id: tenant,
        require_user: true,
        users: [
          %{
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 1,
            "pool_checkout_timeout" => @checkout_timeout,
            "max_clients" => 100,
            "mode_type" => "transaction"
          }
        ]
      })

    on_exit(fn ->
      Supavisor.stop(
        Supavisor.id(type: :single, tenant: tenant, user: db_conf[:username], mode: :transaction)
      )
    end)

    {:ok, tenant: tenant}
  end

  @tag timeout: 120_000
  test "the only worker serves its client's next query without waiting", %{tenant: tenant} do
    sock = connect(tenant)

    for i <- 1..@queries do
      value = Integer.to_string(i)
      :ok = :gen_tcp.send(sock, query("SELECT #{value}::bigint"))

      case recv_rows(sock, "") do
        {:ok, [^value]} -> :ok
        {:ok, rows} -> flunk("query #{i} got #{inspect(rows)}")
        {:error, reason} -> flunk("query #{i} got no answer: #{inspect(reason)}")
      end
    end
  end

  defp recv_rows(sock, buf) do
    with {:ok, more} <- :gen_tcp.recv(sock, 0, 2 * @checkout_timeout) do
      {pkts, _rest} = Supavisor.Protocol.split_pkts(buf <> more)

      cond do
        Enum.any?(pkts, &match?(<<?E, _::binary>>, &1)) ->
          {:error, {:error_response, pkts}}

        Enum.any?(pkts, &match?(<<?Z, _::binary>>, &1)) ->
          {:ok, for(<<?D, _::32, 1::16, len::32, col::binary-size(len)>> <- pkts, do: col)}

        true ->
          recv_rows(sock, buf <> more)
      end
    end
  end

  defp connect(tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)

    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    ProtocolClient.authenticate(sock, "#{db_conf[:username]}.#{tenant}", db_conf[:password])
    sock
  end

  defp query(sql), do: <<?Q, byte_size(sql) + 5::32, sql::binary, 0>>
end
