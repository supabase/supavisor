defmodule Supavisor.Encrypted.Binary do
  use Cloak.Ecto.Binary, vault: Supavisor.Vault
end
