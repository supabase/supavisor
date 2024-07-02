{:ok, _} = Node.start(:"primary@127.0.0.1", :longnames)

Cachex.start_link(name: Supavisor.Cache)

ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(Supavisor.Repo, :auto)
