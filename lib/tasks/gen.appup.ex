defmodule Mix.Tasks.Supavisor.Gen.Appup do
  @moduledoc """
  Generates an appup file for a given release.

  ## Examples

      # Generate an appup from 0.0.1 to 0.0.2 versions

      mix supavisor.gen.appup --from=0.0.1 --to=0.0.2
  """

  use Mix.Task
  alias Distillery.Releases.Appup

  @impl true
  def run(args) do
    {parsed, _, _} = OptionParser.parse(args, strict: [from: :string, to: :string])

    {from_vsn, to_vsn} =
      if !parsed[:from] || !parsed[:to] do
        Mix.Task.run("help", ["supavisor.gen.appup"])
        System.halt(1)
      else
        {parsed[:from], parsed[:to]}
      end

    IO.puts("Generating appup from #{from_vsn} to #{to_vsn}...\n")

    rel_dir = Path.join([File.cwd!(), "_build", "#{Mix.env()}", "rel", "supavisor"])
    lib_path = Path.join(rel_dir, "lib")
    path_from = Path.join(lib_path, "supavisor-#{from_vsn}")
    path_to = Path.join(lib_path, "supavisor-#{to_vsn}")
    appup_path = Path.join([path_to, "ebin", "supavisor.appup"])

    transforms = [Supavisor.HotUpgrade]

    case Appup.make(:supavisor, from_vsn, to_vsn, path_from, path_to, transforms) do
      {:ok, appup} ->
        IO.puts("Writing appup to #{appup_path}")

        case File.write(appup_path, :io_lib.format("~p.", [appup]), [:utf8]) do
          :ok ->
            IO.puts("Appup:\n#{File.read!(appup_path)}")

          {:error, reason} ->
            Mix.raise("Failed to write appup file: #{reason}")
        end

      {:error, reason} ->
        Mix.raise("Failed to generate appup file: #{inspect(reason)}")
    end
  end
end
