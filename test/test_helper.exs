Node.start(:"primary@127.0.0.1", :longnames)
{:ok, _pid, node} = :peer.start(%{name: :"secondary@127.0.0.1"})
true = :erpc.call(node, :code, :set_path, [:code.get_path()])

Supavisor.Support.Cluster.apply_config(node)

{:ok, _} = :erpc.call(node, :application, :ensure_all_started, [:supavisor])

ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(Supavisor.Repo, :manual)
