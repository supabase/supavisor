defmodule Supavisor.Config.RuntimeTest do
  use ExUnit.Case, async: false

  @env_vars ~w(
    SUPAVISOR_LOG_BURST_LIMIT_ENABLE
    SUPAVISOR_LOG_BURST_LIMIT_MAX_COUNT
    SUPAVISOR_LOG_BURST_LIMIT_WINDOW_TIME
    SUPAVISOR_LOG_FILE_PATH
  )

  setup do
    previous = Map.new(@env_vars, &{&1, System.get_env(&1)})

    on_exit(fn ->
      for {var, value} <- previous do
        if value, do: System.put_env(var, value), else: System.delete_env(var)
      end
    end)

    for var <- @env_vars, do: System.delete_env(var)

    :ok
  end

  defp read_config do
    Config.Reader.read!("config/runtime.exs", env: :test, target: :host)
  end

  test "logger burst-limit defaults match OTP's own defaults when env vars are unset" do
    config = read_config()

    assert config[:logger][:default_handler][:config] == [
             burst_limit_enable: true,
             burst_limit_max_count: 500,
             burst_limit_window_time: 1000
           ]
  end

  test "logger burst-limit env vars override the defaults" do
    System.put_env("SUPAVISOR_LOG_BURST_LIMIT_ENABLE", "false")
    System.put_env("SUPAVISOR_LOG_BURST_LIMIT_MAX_COUNT", "7")
    System.put_env("SUPAVISOR_LOG_BURST_LIMIT_WINDOW_TIME", "333")

    config = read_config()

    assert config[:logger][:default_handler][:config] == [
             burst_limit_enable: false,
             burst_limit_max_count: 7,
             burst_limit_window_time: 333
           ]
  end

  test "SUPAVISOR_LOG_BURST_LIMIT_ENABLE only treats \"true\"/\"1\" as enabled" do
    for {value, expected} <- [
          {"true", true},
          {"1", true},
          {"false", false},
          {"0", false},
          {"nope", false}
        ] do
      System.put_env("SUPAVISOR_LOG_BURST_LIMIT_ENABLE", value)

      config = read_config()

      assert config[:logger][:default_handler][:config][:burst_limit_enable] == expected,
             "expected SUPAVISOR_LOG_BURST_LIMIT_ENABLE=#{value} to resolve to #{expected}"
    end
  end

  test "burst-limit config coexists with the log-file-path config instead of clobbering it" do
    System.put_env("SUPAVISOR_LOG_FILE_PATH", "/tmp/supavisor-runtime-config-test.log")
    System.put_env("SUPAVISOR_LOG_BURST_LIMIT_MAX_COUNT", "42")

    default_handler_config = read_config()[:logger][:default_handler][:config]

    assert default_handler_config[:file] == ~c"/tmp/supavisor-runtime-config-test.log"
    assert default_handler_config[:burst_limit_max_count] == 42
  end
end
