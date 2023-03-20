Node.start(:"primary@127.0.0.1", :longnames) |> IO.inspect()
node2 = :"secondary@127.0.0.1"
:ct_slave.start(node2) |> IO.inspect()
:timer.sleep(1000)
true = :erpc.call(node2, :code, :set_path, [:code.get_path()])

Supavisor.Support.Cluster.apply_config(node2)

{:ok, _} = :erpc.call(node2, :application, :ensure_all_started, [:supavisor])

ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(Supavisor.Repo, :manual)
