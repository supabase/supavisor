defmodule Supavisor.Monitoring.OpenTelemetry do
  @moduledoc """
  Thin wrapper around the OpenTelemetry API for the connection-handling hot
  path.

  OpenTelemetry support is opt-in: when `OTEL_EXPORTER_OTLP_ENDPOINT` is
  unset, the underlying tracer is configured as a no-op (see
  `config/runtime.exs`), so the helpers here become near-zero-cost — but the
  call sites remain unconditional, which keeps the codebase Dialyzer-clean
  (see PR #102 for context on why conditional compilation was rejected).

  All spans created here are scoped to the `supavisor` instrumentation
  library and use semantic attributes that are stable across releases:

    * `supavisor.tenant`
    * `supavisor.user`
    * `supavisor.mode`            — `:transaction` | `:session` | `:proxy`
    * `supavisor.type`            — `:single` | `:cluster`
    * `supavisor.db_name`
    * `supavisor.query_proxy`     — true when query was proxied to another
                                    node
    * `supavisor.checkout.same_box` — `:local` | `:remote`
  """

  require OpenTelemetry.Tracer, as: Tracer
  require Supavisor

  @typep id_or_tags :: Supavisor.id() | map() | keyword()

  @doc """
  Run `fun` inside a span named `name`.

  `attrs_or_id` may be either a `Supavisor.id` record (in which case it is
  flattened into a stable set of attributes) or a plain map/keyword list.

  When OpenTelemetry is not configured, this is effectively a function call
  that runs `fun.()` and returns its result; the SDK short-circuits the
  span creation to a no-op tracer.
  """
  @spec with_span(String.t(), id_or_tags(), (-> result)) :: result when result: var
  def with_span(name, attrs_or_id, fun) when is_binary(name) and is_function(fun, 0) do
    Tracer.with_span(name, %{attributes: to_attributes(attrs_or_id)}, fn _span_ctx ->
      try do
        result = fun.()
        record_result(result)
        result
      rescue
        error ->
          set_error(error, __STACKTRACE__)
          reraise error, __STACKTRACE__
      end
    end)
  end

  @doc """
  Add an event to the currently-active span.

  Useful for marking transitions during a long-lived span — for example,
  authentication completing during the client_join span.
  """
  @spec add_event(String.t(), map() | keyword()) :: :ok
  def add_event(event_name, attrs \\ %{}) when is_binary(event_name) do
    Tracer.add_event(event_name, normalise_attrs(attrs))
    :ok
  end

  @doc """
  Set additional attributes on the currently-active span.
  """
  @spec set_attributes(map() | keyword()) :: :ok
  def set_attributes(attrs) do
    Tracer.set_attributes(normalise_attrs(attrs))
    :ok
  end

  # ---- private --------------------------------------------------------------

  # Tag a span as errored when an exception is raised inside it. The OTel
  # convention is to mark the span status :error and record the exception as
  # an event with an `exception.*` attribute set.
  defp set_error(error, stacktrace) do
    Tracer.record_exception(error, stacktrace)
    Tracer.set_status(:error, Exception.message(error))
  end

  # Some helpers return `{:ok, _}` / `{:error, _}`. When we see a tagged
  # error tuple, propagate it onto the span as a status — without this, the
  # span looks "successful" even when the operation logically failed.
  defp record_result({:error, reason}) do
    Tracer.set_status(:error, inspect_reason(reason))
  end

  defp record_result(_), do: :ok

  defp inspect_reason(reason) when is_binary(reason), do: reason
  defp inspect_reason(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp inspect_reason(reason), do: inspect(reason)

  # Convert a Supavisor.id record into the canonical attribute set. We strip
  # `nil` values to avoid noisy spans, and keep the set narrow enough that
  # a tenant/user pair is always queryable in any backend.
  defp to_attributes(
         Supavisor.id(
           type: type,
           tenant: tenant,
           user: user,
           mode: mode,
           db: db_name,
           search_path: search_path
         )
       ) do
    %{
      "supavisor.type" => to_value(type),
      "supavisor.tenant" => to_value(tenant),
      "supavisor.user" => to_value(user),
      "supavisor.mode" => to_value(mode),
      "supavisor.db_name" => to_value(db_name),
      "supavisor.search_path" => to_value(search_path)
    }
    |> drop_nils()
  end

  defp to_attributes(attrs) when is_map(attrs), do: normalise_attrs(attrs)
  defp to_attributes(attrs) when is_list(attrs), do: normalise_attrs(attrs)
  defp to_attributes(_), do: %{}

  defp normalise_attrs(attrs) when is_list(attrs), do: attrs |> Map.new() |> normalise_attrs()

  defp normalise_attrs(attrs) when is_map(attrs) do
    attrs
    |> Enum.map(fn {k, v} -> {to_attr_key(k), to_value(v)} end)
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp to_attr_key(k) when is_atom(k), do: Atom.to_string(k)
  defp to_attr_key(k) when is_binary(k), do: k

  # OTel attribute values must be primitives or lists of primitives. Atoms
  # (`:transaction`, `:session`, …) are stringified so they survive export.
  defp to_value(nil), do: nil
  defp to_value(v) when is_atom(v) and v not in [true, false], do: Atom.to_string(v)
  defp to_value(v) when is_binary(v) or is_number(v) or is_boolean(v), do: v
  defp to_value(v), do: inspect(v)

  defp drop_nils(map) do
    map
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new()
  end
end
