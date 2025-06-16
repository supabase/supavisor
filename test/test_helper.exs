{:ok, _} = Node.start(:"primary@127.0.0.1", :longnames)

Cachex.start_link(name: Supavisor.Cache)

logs =
  case System.get_env("TEST_LOGS", "all") do
    level when level in ~w[all true] ->
      true

    level when level in ~w[emergency alert critical error warning notice info debug] ->
      [level: String.to_existing_atom(level)]

    "warn" ->
      [level: :warning]

    level when level in ~w[none disabled false] ->
      false
  end

ExUnit.start(
  capture_log: logs,
  exclude: [
    flaky: true,
    integration: true
  ]
)

Ecto.Adapters.SQL.Sandbox.mode(Supavisor.Repo, :auto)
