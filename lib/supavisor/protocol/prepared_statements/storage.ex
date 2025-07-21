defmodule Supavisor.Protocol.PreparedStatements.Storage do
  @moduledoc """
  Client-side storage abstraction for prepared statements.
  """

  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.PreparedStatement

  @type t() ::
          {size :: non_neg_integer(),
           %{PreparedStatements.statement_name() => PreparedStatement.t()}}

  @spec new() :: t()
  def new do
    {0, %{}}
  end

  @spec put(t(), PreparedStatements.statement_name(), PreparedStatement.t()) :: t()
  def put({size, statements}, statement_name, statement) do
    new_size = size + PreparedStatement.size(statement)
    {new_size, Map.put(statements, statement_name, statement)}
  end

  @spec get(t(), PreparedStatements.statement_name()) :: PreparedStatement.t() | nil
  def get({_size, statements}, statement_name) do
    Map.get(statements, statement_name)
  end

  @spec pop(t(), PreparedStatements.statement_name()) :: {PreparedStatement.t() | nil, t()}
  def pop({size, statements}, statement_name) do
    {statement, new_statements} = Map.pop(statements, statement_name)
    new_size = size - PreparedStatement.size(statement)
    {statement, {new_size, new_statements}}
  end

  @spec statement_count(t()) :: non_neg_integer()
  def statement_count({_size, statements}) do
    map_size(statements)
  end

  @spec statement_memory(t()) :: non_neg_integer()
  def statement_memory({size, _statements}) do
    size
  end
end
