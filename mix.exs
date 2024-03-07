defmodule Supavisor.MixProject do
  use Mix.Project

  def project do
    [
      app: :supavisor,
      version: version(),
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      releases: releases(),
      dialyzer: [plt_add_apps: [:mix]]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Supavisor.Application, []},
      extra_applications: [:logger, :runtime_tools, :os_mon, :ssl]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:phoenix, "~> 1.7.2"},
      {:phoenix_ecto, "~> 4.4"},
      {:ecto_sql, "~> 3.10"},
      {:postgrex, ">= 0.0.0"},
      {:phoenix_html, "~> 3.0"},
      {:phoenix_view, "~> 2.0.2"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 0.18.18"},
      {:phoenix_live_dashboard, "~> 0.7"},
      {:telemetry_metrics, "~> 0.6"},
      {:telemetry_poller, "~> 1.0"},
      {:jason, "~> 1.2"},
      {:plug_cowboy, "~> 2.5"},
      {:joken, "~> 2.5.0"},
      {:cloak_ecto, "~> 1.2.0"},
      {:meck, "~> 0.9.2", only: :test},
      {:credo, "~> 1.6.4", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.1.0", only: [:dev], runtime: false},
      {:benchee, "~> 1.1.0", only: :dev},
      {:prom_ex, "~> 1.8.0"},
      {:open_api_spex, "~> 3.16"},
      {:burrito, github: "burrito-elixir/burrito"},
      {:libcluster, "~> 3.3.1"},
      {:logflare_logger_backend, github: "Logflare/logflare_logger_backend", tag: "v0.11.4"},
      {:distillery, "~> 2.1"},
      {:cachex, "~> 3.6"},
      {:inet_cidr, "~> 1.0.0"},
      {:observer_cli, "~> 1.7"},

      # pooller
      # {:poolboy, "~> 1.5.2"},
      {:poolboy, git: "https://github.com/abc3/poolboy.git", tag: "v0.0.2"},
      {:syn, "~> 3.3"},
      {:pgo, "~> 0.13"},
      {:rustler, "~> 0.29.1"}
      # TODO: add ranch deps
    ]
  end

  def releases do
    [
      supavisor: [
        steps: [:assemble, &upgrade/1, :tar],
        include_erts: System.get_env("INCLUDE_ERTS", "true") == "true",
        cookie: System.get_env("RELEASE_COOKIE", Base.url_encode64(:crypto.strong_rand_bytes(30)))
      ],
      supavisor_bin: [
        steps: [:assemble, &Burrito.wrap/1],
        burrito: [
          targets: [
            macos_aarch64: [os: :darwin, cpu: :aarch64],
            macos_x86_64: [os: :darwin, cpu: :x86_64],
            linux_x86_64: [os: :linux, cpu: :x86_64],
            linux_aarch64: [os: :linux, cpu: :aarch64]
          ]
        ]
      ]
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      # test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
      test: [
        "ecto.create",
        "run priv/repo/seeds_before_migration.exs",
        "ecto.migrate --prefix _supavisor --log-migrator-sql",
        "run priv/repo/seeds_after_migration.exs",
        "test"
      ]
    ]
  end

  defp upgrade(release) do
    from = System.get_env("UPGRADE_FROM")

    if from && from != "" do
      vsn = release.version
      path = Path.join([release.path, "releases", "supavisor-#{vsn}.rel"])
      rel_content = File.read!(Path.join(release.version_path, "supavisor.rel"))

      Mix.Task.run("supavisor.gen.appup", ["--from=" <> from, "--to=" <> vsn])
      :ok = File.write!(path, rel_content)
      Mix.Task.run("supavisor.gen.relup", ["--from=" <> from, "--to=" <> vsn])
    end

    release
  end

  defp version, do: File.read!("./VERSION") |> String.trim()
end
