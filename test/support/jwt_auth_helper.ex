defmodule Supavisor.Support.JWTAuthHelper do
  @moduledoc """
  Test helper to observe `Supavisor.JWT`'s `[:supavisor, :jwt_auth, :ok | :rejected]`
  telemetry events.

  Telemetry handlers run in the process that calls `:telemetry.execute/3`, so for
  a request handled by the test process the event is already in its mailbox when
  the call returns: `assert_received`/`refute_received` are deterministic and
  `refute_receive` would only add a timeout.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  @events [[:supavisor, :jwt_auth, :ok], [:supavisor, :jwt_auth, :rejected]]

  @doc """
  Sends `{ref, event_name, measurements, meta}` to the calling process for every
  JWT auth event, until the test exits. Returns `ref`.
  """
  @spec attach_jwt_auth_telemetry_handler() :: reference()
  def attach_jwt_auth_telemetry_handler do
    ref = make_ref()

    :telemetry.attach_many(
      {ref, :jwt_auth},
      @events,
      &__MODULE__.handle_jwt_auth_event/4,
      {self(), ref}
    )

    on_exit(fn -> :telemetry.detach({ref, :jwt_auth}) end)

    ref
  end

  @doc false
  def handle_jwt_auth_event(event, measurements, meta, {pid, ref}) do
    send(pid, {ref, event, measurements, meta})
  end
end
