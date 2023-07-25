defmodule Supavisor.Release do
  @moduledoc """
  Used for executing DB release tasks when run in production without Mix
  installed.
  """
  @app :supavisor

  def migrate do
    ensure_ssl_started()

    for repo <- repos() do
      {:ok, _, _} =
        Ecto.Migrator.with_repo(
          repo,
          &Ecto.Migrator.run(&1, :up, all: true, prefix: "_supavisor")
        )
    end
  end

  def rollback(repo, version) do
    ensure_ssl_started()

    {:ok, _, _} =
      Ecto.Migrator.with_repo(
        repo,
        &Ecto.Migrator.run(&1, :down, to: version, prefix: "_supavisor")
      )
  end

  defp repos do
    Application.fetch_env!(@app, :ecto_repos)
  end

  defp ensure_ssl_started do
    Application.ensure_all_started(:ssl)
  end
end
