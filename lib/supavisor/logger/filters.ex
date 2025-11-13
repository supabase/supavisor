defmodule Supavisor.Logger.Filters do
  @moduledoc """
  Useful logger filters.
  """

  @doc """
  Log event only when it has the `auth_error` metadata set to true
  """
  @spec filter_auth_error(:logger.log_event(), term()) :: :logger.filter_return()
  def filter_auth_error(log_event, _states) do
    case log_event do
      %{meta: %{auth_log: true}} ->
        log_event

      _ ->
        :ignore
    end
  end
end
