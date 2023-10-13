The metrics feature provides a range of metrics in the Prometheus format. The main modules involved in this implementation are:

- `Supavisor.Monitoring.PromEx`
- `Supavisor.PromEx.Plugins.OsMon`
- `Supavisor.PromEx.Plugins.Tenant`
- `Supavisor.Monitoring.Telem`

## Metrics exposed

The exposed metrics include the following:

- Application
- BEAM
- Phoenix
- Ecto
- System monitoring metrics:
  - CPU utilization
  - RAM usage
  - Load average (LA)
- Pool checkout queue time
- Number of connected clients
- Query duration and query counts
- Network usage for client sockets and database sockets

## Usage

To use the metrics feature, send an HTTP request to the `/metrics` endpoint. The endpoint is secured using Bearer authentication, which requires a JSON Web Token (JWT) generated using the `METRICS_JWT_SECRET` environment variable. Make sure to set this environment variable with a secure secret key.

When a node receives a request for metrics, it polls all nodes in the cluster, accumulates their metrics, and appends service tags such as region and host. To generate a valid JWT, use a library or tool that supports JWT creation with the HS256 algorithm and the `METRICS_JWT_SECRET` as the secret key.

Remember to keep the `METRICS_JWT_SECRET` secure and only share it with authorized personnel who require access to the metrics endpoint.
