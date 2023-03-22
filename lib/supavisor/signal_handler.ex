defmodule Supavisor.SignalHandler do
  @moduledoc """
  Supavisor.SignalHandler is a module that provides a custom signal handling behavior
  for the Supavisor application. It implements the :gen_event behavior and intercepts
  system signals, such as SIGTERM, to manage application state during shutdown.

  The module ensures that the shutdown process is properly communicated to the rest
  of the application by updating the :shutdown_in_progress environment variable.
  """

  @behaviour :gen_event
  require Logger

  @spec shutdown_in_progress?() :: boolean()
  def shutdown_in_progress? do
    !!Application.get_env(:supavisor, :shutdown_in_progress)
  end

  @impl true
  def init(_) do
    Logger.info("#{__MODULE__} is being initialized...")
    {:ok, %{}}
  end

  @impl true
  def handle_event(signal, state) do
    Logger.warn("#{__MODULE__}: #{inspect(signal)} received")

    if signal == :sigterm do
      Application.put_env(:supavisor, :shutdown_in_progress, true)
    end

    :erl_signal_handler.handle_event(signal, state)
  end

  @impl true
  defdelegate handle_info(info, state), to: :erl_signal_handler

  @impl true
  defdelegate handle_call(request, state), to: :erl_signal_handler
end
