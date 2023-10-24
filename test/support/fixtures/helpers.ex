defmodule Supavisor.FixturesHelpers do
  @moduledoc false

  def start_pool(id, secret, db_name) do
    secret = {:password, fn -> secret end}
    Supavisor.start(id, secret, db_name)
  end
end
