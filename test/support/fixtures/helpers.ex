defmodule Supavisor.FixturesHelpers do
  @moduledoc false

  def start_pool(id, secret) do
    secret = {:password, fn -> secret end}
    Supavisor.start(id, secret)
  end
end
