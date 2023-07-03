defmodule Mix.Tasks.Supavisor.Gen.Tarball do
  @moduledoc """
  Generates a tarball for a given release of a project.

  ## Examples

    # Generate a tarball for version 0.0.1

    mix supavisor.gen.tarball --vsn=0.0.1
  """

  use Mix.Task

  @impl true
  def run(args) do
    {parsed, _, _} = OptionParser.parse(args, strict: [vsn: :string])

    vsn =
      if !parsed[:vsn] do
        Mix.Task.run("help", ["supavisor.gen.tarball"])
        System.halt(1)
      else
        parsed[:vsn]
      end

    IO.puts("Generating tarball for #{vsn}...\n")

    rel_dir = Path.join([File.cwd!(), "_build", "#{Mix.env()}", "rel", "supavisor"])
    curr_rel_dir = Path.join([rel_dir, "releases", vsn])
    lib_path = Path.join(rel_dir, "lib")

    rel_file_path = Path.join(File.cwd!(), "supavisor-#{vsn}.rel")

    File.write(
      rel_file_path,
      Path.join(curr_rel_dir, "supavisor.rel") |> File.read!()
    )

    :ok =
      :systools.make_tar(to_charlist("supavisor-#{vsn}"), [
        {:path,
         [
           to_charlist(curr_rel_dir),
           Path.join(lib_path, "/*/ebin") |> to_charlist(),
           Path.join(curr_rel_dir, "/*") |> to_charlist()
         ]}
      ])

    tmpdir = Path.join(File.cwd!(), "/tmp")

    File.rm_rf(tmpdir)
    File.mkdir!(tmpdir)

    arch_name = Path.join(File.cwd!(), "supavisor-#{vsn}.tar.gz") |> to_charlist()

    :ok = :erl_tar.extract(arch_name, [:compressed, {:cwd, tmpdir}, {:verbose, false}])

    tmpdir_rel = Path.join([tmpdir, "releases", vsn])

    Path.wildcard("#{curr_rel_dir}/**")
    |> Enum.each(fn path ->
      relative = Path.relative_to(path, curr_rel_dir)

      tmp_path = Path.join(tmpdir_rel, relative)

      if File.dir?(path) && !File.dir?(tmp_path) do
        File.mkdir!(tmp_path)
      else
        if !File.exists?(tmp_path) do
          File.cp!(path, tmp_path)
        end
      end
    end)

    {:ok, tar} = :erl_tar.open(arch_name, [:write, :compressed])

    for path <- Path.wildcard("#{tmpdir}/**") do
      if !File.dir?(path) do
        relative = Path.relative_to(path, tmpdir)
        :erl_tar.add(tar, to_charlist(path), to_charlist(relative), [])
      end
    end
    |> then(&"Added #{length(&1)} files")
    |> IO.puts()

    :ok = :erl_tar.close(tar)
    {:ok, _} = File.rm_rf(tmpdir)
    :ok = File.rm(rel_file_path)

    if File.exists?(arch_name) do
      IO.puts("Tarball generated successfully at #{arch_name}")
    else
      Mix.raise("Tarball generation failed")
    end
  end
end
