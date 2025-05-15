defmodule Supavisor.Logger.Filters do
  @moduledoc """
  Useful logger filters.
  """

  @doc """
  Log events that are fired by `Supavisor.ClientHandler` only when the module
  state is equal to `state`.
  """
  def filter_client_handler(log_event, state) do
    %{meta: meta} = log_event

    case meta do
      %{mfa: {Supavisor.ClientHandler, _, _}, state: ^state} ->
        log_event

      _ ->
        :ignore
    end
  end
end
