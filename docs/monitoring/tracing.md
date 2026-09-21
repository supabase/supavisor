# OpenTelemetry tracing

Tracing is optional and is not included in the default build. To include the
OpenTelemetry SDK and OTLP exporter, fetch dependencies and build a release with
`MIX_TARGET=otel`:

```sh
MIX_TARGET=otel mix deps.get
MIX_TARGET=otel MIX_ENV=prod mix release
```

For the Docker image, pass `--build-arg MIX_TARGET=otel` to `docker build`.

Set `ENABLE_OTEL=true` when starting that release, and configure the collector
using the standard `OTEL_EXPORTER_OTLP_ENDPOINT` and
`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` environment variables. Set
`OTEL_SERVICE_NAME=supavisor` to identify the service in the collector. Enabling
tracing on a default build fails at startup with a message explaining the
required build target.

Supavisor emits `supavisor.connect` spans for client handshakes and
`supavisor.query` spans for query handling in session and transaction modes.
Query spans include a `pool.checkout` event with its outcome and duration.
Interrupted connections and queries have error status. Span attributes include
the tenant, pool mode, and database name when available; SQL text and credentials
are not recorded.

Tracing is independent of the existing Prometheus metrics endpoints. It is
disabled unless explicitly enabled, even in an OpenTelemetry build.
