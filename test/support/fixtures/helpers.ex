defmodule Supavisor.FixturesHelpers do
  @moduledoc false

  alias Supavisor.EncryptedSecrets

  def start_pool(id, secret) do
    encrypted = EncryptedSecrets.encrypt(secret)
    Supavisor.start(id, encrypted)
  end
end
