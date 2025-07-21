defmodule Supervisor.ReleaseHooks do
  @moduledoc """
  Hooks for soft releases. These functions should be called when the doing
  soft updates, and may impact the update process.
  """

  require Logger

  @type version :: String.t()

  @doc """
  Should be called before the release is installed.

  If this functions returns error, the installation should be aborted.

  Notice that the version of this function that will run will be the one from the
  **old version**, not the one from the new version.
  """
  @spec pre_install(version, version) :: :ok | :error
  def pre_install(_previous_version, new_version) do
    Logger.info("Starting #{inspect(new_version)} installation")
  end

  @doc """
  Should be called after the release is installed.

  If this functions return error, the release should be rolled back.

  It can be an opportunity to validate that the installation went correctly, and that
  the system is behaving as expected.

  Notice that the version of this function that will run will be the one from the
  **new version**, not the one from the old version.
  """
  @spec post_install(version, version) :: :ok | :error
  def post_install(_previous_version, new_version) do
    Logger.info("Release #{inspect(new_version)} installed")
  end

  @doc """
  Should be called after the release is made permanent.

  Notice that the version of this function that will run will be the one from the
  **new version**, not the one from the old version.
  """
  @spec post_make_permanent(version, version) :: :ok
  def post_make_permanent(_previous_version, new_version) do
    Logger.info("Release #{inspect(new_version)} made permanent")
    refresh_manual_metrics()
  end

  defp refresh_manual_metrics do
    PromEx.ManualMetricsManager.refresh_metrics(PromEx.Plugins.Application)
  end
end
