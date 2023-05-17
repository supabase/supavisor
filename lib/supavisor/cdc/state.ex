defmodule Supavisor.CDC.State do
  @moduledoc """
  This module stores state for CDC.

  The struct is owned by ClientHandler but updated by the CDC context.

  * in_transaction?: true if we are in a transaction
  * client_packets: the packets we have received from the client (psql, etc.)
  * server_packets: the packets we have received from the server (postgres)
  """

  @enforce_keys [:db_namespace]
  defstruct client_packets: [], db_namespace: nil, in_transaction?: false, server_packets: []
end
