defmodule Supavisor.Errors.InvalidStartupOptionError do
  @moduledoc """
  This error is returned when client sends an invalid startup option
  """

  use Supavisor.Error, [:name, :value, code: "EINVALIDSTARTUPOPTION"]

  alias Supavisor.Protocol.StartupOptions

  @type t() :: %__MODULE__{
          name: binary(),
          value: binary(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{name: name, value: value}) do
    {message, _hint} = StartupOptions.invalid_option_message({name, value})
    message
  end

  @impl Supavisor.Error
  def postgres_error(%{name: name, value: value}) do
    {message, hint} = StartupOptions.invalid_option_message({name, value})
    base = %{"S" => "FATAL", "V" => "FATAL", "C" => "22023", "M" => message}

    if hint, do: Map.put(base, "H", hint), else: base
  end
end
