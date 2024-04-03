defmodule Supavisor.FixturesHelpers do
  @moduledoc false

  alias Supavisor.Helpers, as: H

  def start_pool(id, secret) do
    secret = {:password, H.encode_secret(secret)}
    Supavisor.start(id, secret)
  end
end
