{:ok, _} = Node.start(:"primary@127.0.0.1", :longnames)

Cachex.start_link(name: Supavisor.Cache)

auth_profiles_conf = Application.get_env(:supavisor, :test_auth_profiles)

Supavisor.PasswordRepo.start_link(elem(auth_profiles_conf[:password], 0))

Supavisor.MD5Repo.start_link(elem(auth_profiles_conf[:md5], 0))

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
    integration: true,
    integration_docker: true
  ]
)

Ecto.Adapters.SQL.Sandbox.mode(Supavisor.Repo, :auto)
