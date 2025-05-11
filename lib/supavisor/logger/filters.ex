defmodule Supavisor.Logger.Filters do
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
