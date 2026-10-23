defmodule Supavisor.ClientHandler.ConnectionRequest do
  @moduledoc """
  Records the outcome of a client connection request, at most once per ClientHandler process.

  A request ends when greetings are sent (`ok/1`) or when the handler stops before that (`error/2`).
  The once-only guard lives in the process dictionary so the `terminate/3` safety net can tell
  whether a more specific exit already recorded the outcome.
  """

  alias Supavisor.Monitoring.Telem

  @key __MODULE__

  @doc """
  Records a successful request. No-op once an outcome was recorded.

  A proxying handler (mode `:proxy`) is skipped: the pool node's handler records the request.
  """
  @spec ok(map()) :: :ok
  def ok(%{mode: :proxy}), do: ignore()
  def ok(data), do: record(data, :ok, nil)

  @doc """
  Records a failed request, taking `fault` and `code` from the exception.

  A proxying handler only records errors it classified itself. Its other exits (the pool node's
  handler already recorded those) are skipped.
  """
  @spec error(map(), term()) :: :ok
  def error(%{mode: :proxy}, reason) when not is_exception(reason), do: ignore()
  def error(data, exception), do: record(data, :error, exception)

  @doc "Marks the process as not being a connection request (HTTP probes, cancel requests)."
  @spec ignore() :: :ok
  def ignore do
    Process.put(@key, true)
    :ok
  end

  @doc "True while no outcome has been recorded."
  @spec pending?() :: boolean()
  def pending?, do: Process.get(@key) != true

  defp record(data, outcome, exception) do
    if pending?() do
      Process.put(@key, true)

      Telem.client_connection_request(
        data.connection_start,
        outcome,
        tags(exception, data.mode)
      )
    else
      :ok
    end
  end

  defp tags(nil, mode), do: %{code: "", reason: "", fault: "", mode: mode}

  defp tags(exception, mode) when is_exception(exception) do
    %{
      code: exception.code,
      reason: reason(exception),
      fault: exception.__struct__.fault(exception),
      mode: mode
    }
  end

  # Anything that is not a Supavisor.Error is an unexpected failure on our side
  defp tags(_other, mode), do: %{code: "internal", reason: "", fault: :supavisor, mode: mode}

  # Only the checkout timeout has a bounded reason worth a label; other `reason` fields hold arbitrary terms
  defp reason(%Supavisor.Errors.CheckoutTimeoutError{reason: reason}) when is_atom(reason),
    do: reason || ""

  defp reason(_), do: ""
end
