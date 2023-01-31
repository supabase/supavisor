defmodule PgEdge.Encrypted.Binary do
  use Cloak.Ecto.Binary, vault: PgEdge.Vault
end
