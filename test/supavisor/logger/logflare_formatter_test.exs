defmodule Supavisor.Logger.LogflareFormatterTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  require Logger

  @subject Supavisor.Logger.LogflareFormatter

  doctest @subject

  defmodule FakeLogger do
    @behaviour :logger_handler

    def install(id, opts) do
      pid = start_supervised!({Agent, fn -> [] end})

      :logger.add_handler(
        id,
        __MODULE__,
        Map.merge(opts, %{
          config: %{pid: pid}
        })
      )

      on_exit(fn -> :logger.remove_handler(id) end)

      pid
    end

    def get(pid) do
      Enum.reverse(Agent.get(pid, fn state -> state end))
    end

    def log(le, config) do
      %{
        formatter: {fmod, fopts},
        config: %{pid: pid}
      } = config

      entry = fmod.format(le, fopts)

      Agent.update(pid, fn state -> [IO.iodata_to_binary(entry) | state] end)
    end
  end

  test "simple" do
    pid = FakeLogger.install(:fake_logger, %{formatter: {@subject, %{}}})

    Logger.info("foo")

    assert [event] = FakeLogger.get(pid)

    assert {:ok, _event} = JSON.decode(event)
  end

  test "regression: mfa in context is a string array" do
    pid = FakeLogger.install(:fake_logger, %{formatter: {@subject, %{}}})

    Logger.info("foo")

    assert [event] = FakeLogger.get(pid)

    assert {:ok, event} = JSON.decode(event)

    assert event["metadata"]["context"]["mfa"] == [
             inspect(__ENV__.module),
             to_string(elem(__ENV__.function, 0)),
             to_string(elem(__ENV__.function, 1))
           ]
  end

  test "regression: level is inside metadata" do
    pid = FakeLogger.install(:fake_logger, %{formatter: {@subject, %{}}})

    Logger.info("foo")

    assert [event] = FakeLogger.get(pid)

    assert {:ok, event} = JSON.decode(event)

    assert event["metadata"]["level"] == "info"
  end
end
