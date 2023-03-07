defmodule Supavisor.PgProtocol do
  @moduledoc false
  require Logger

  @spec ready_for_query?(binary) :: boolean
  def ready_for_query?(bin) do
    String.slice(bin, (byte_size(bin) - 6)..-1) == <<?Z, 0, 0, 0, 5, ?I>>
  end
end
