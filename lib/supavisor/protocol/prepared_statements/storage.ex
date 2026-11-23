defmodule Supavisor.Protocol.PreparedStatements.Storage do
  @moduledoc """
  Client-side storage abstraction for prepared statements.
  """

  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.PreparedStatement

  # put/3 pops first. Inlined, the tuples pop/2 returns are never built.
  @compile {:inline, pop: 2}

  @statement_limit 100
  @memory_limit_bytes 1_000_000

  @type t() ::
          {size :: non_neg_integer(),
           %{PreparedStatements.statement_name() => PreparedStatement.t()}}

  @spec new() :: t()
  def new do
    {0, %{}}
  end

  @spec put(t(), PreparedStatements.statement_name(), PreparedStatement.t()) ::
          {:ok, t()}
          | {:error, Supavisor.Errors.MaxPreparedStatementsError.t()}
          | {:error, Supavisor.Errors.MaxPreparedStatementsMemoryError.t()}
  def put(storage, statement_name, statement) do
    # A stored name is replaced: its Parse may have been failed or skipped by the backend.
    {_replaced, {size, statements}} = pop(storage, statement_name)
    new_size = size + PreparedStatement.size(statement)

    cond do
      map_size(statements) >= @statement_limit ->
        {:error, %Supavisor.Errors.MaxPreparedStatementsError{limit: @statement_limit}}

      new_size > @memory_limit_bytes ->
        {:error,
         %Supavisor.Errors.MaxPreparedStatementsMemoryError{
           limit_mb: @memory_limit_bytes / 1_000_000
         }}

      true ->
        {:ok, {new_size, Map.put(statements, statement_name, statement)}}
    end
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

  @spec statement_limit() :: pos_integer()
  def statement_limit, do: @statement_limit

  @spec memory_limit_bytes() :: pos_integer()
  def memory_limit_bytes, do: @memory_limit_bytes
end
