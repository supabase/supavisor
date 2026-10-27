# Security Policy

Thank you for helping keep Supavisor and its users safe.

## Reporting a vulnerability

Please report suspected vulnerabilities through our HackerOne program:
<https://hackerone.com/supabase>. Please do not open public GitHub issues or
pull requests for security problems.

This repository contains Supavisor, the Postgres connection pooler that sits
between clients and tenant databases. It authenticates clients, keeps pools
of server connections per tenant in session and transaction modes, and has an
HTTP API for managing tenants and reading metrics. It runs as the connection
pooler on the hosted Supabase platform and is also run by people who self-host
it. We accept reports for both, and we triage them differently (see "Hosted
vs. self-hosted" below).

## What we consider a vulnerability

In general, we want to hear about anything that lets an attacker get through
the pooler to something they are not allowed to reach: connecting to a tenant
database without valid credentials, acting as a different database user or
tenant than the one they authenticated as, seeing another tenant's or another
database user's traffic, or controlling the pooler's management API. The
problem should be present on the hosted pooler or in a default or documented
configuration.

Examples of what this includes (these are illustrations, not a complete list):

- **Authentication bypass.** Getting a server connection to a tenant database
  without the right password or credentials for the user you connect as.
- **Crossing tenants or users.** Being routed to another tenant's database, or
  receiving query results, notifications or session state that belong to a
  client connected as a different database user or to a different tenant.
- **Management API access.** Reaching tenant management or other
  administrative endpoints without a valid token, or using a token for more
  than it allows.
- **Secrets exposed to someone who should not see them.** Tenant database
  passwords, authentication secrets or tokens in API responses, metrics, logs
  or error messages.
- **Crashing the pooler for other tenants.** Input from an unprivileged client
  that takes down or exhausts the pooler for tenants other than the
  attacker's own.

## What we do not consider a vulnerability

Reports that rely on the behavior below will normally be closed as
informative or not applicable.

**By design**

- **Upstream TLS certificates are not verified by default.** This matches the
  default behavior of Postgres clients. Each tenant can be configured with a
  trusted CA so that the certificate is fully verified. Exploiting the default
  needs an attacker on the network between the pooler and the database, which
  is also covered by the program-wide MITM exclusion.
- **The API documentation UI is public.** The Swagger UI page describes the
  same API that is documented in this open source repository. Its presence,
  and the `configUrl` parameter it accepts, are not vulnerabilities unless you
  show the supplied URL being fetched and causing real impact.
- **Transaction mode shares server connections.** In transaction mode, a
  server connection is handed to another client between transactions, as in
  other Postgres poolers. Session-level state does not belong to one client
  there. Use session mode when you need session state.

**Prerequisites that make the attack pointless**

- The attacker needs the management API's signing secret or a valid
  management token, a tenant's database password, or access to the internal
  network between the pooler and the database.
- The attacker needs to change the pooler's configuration or code first.
- The effect stays between clients that connect as the same database user to
  the same tenant. Each of those clients can already read and change the same
  data, so we treat this as a data integrity bug rather than an access control
  break. Show a different user or tenant on the other side.

**Reports that are not evidence of a flaw**

- **Source reading without a working PoC.** Findings shown only by reading the
  code, with no request or connection against a running pooler, are closed.
- **Unreviewed AI output** that was not run against a real deployment.

## Out of scope for every Supabase asset

These are excluded program-wide (see also
<https://supabase.com/.well-known/security.txt>). They are repeated here so
you do not need to leave this repository to find them.

- Clickjacking on pages with no sensitive actions.
- Unauthenticated, logout and login CSRF.
- Attacks requiring MITM or physical access to a user's device.
- Attacks requiring social engineering.
- Any activity that could lead to the disruption of our service (DoS).
  This means volumetric attacks, load testing and flooding. A vulnerability in
  our code that lets an unprivileged attacker crash a service or exhaust
  resources for other users or tenants is in scope. Denial of service that only
  affects the attacker's own project, or that needs admin or owner privileges,
  is not.
- Content spoofing and text injection issues without showing an attack vector,
  or without being able to modify HTML/CSS.
- Email spoofing.
- Missing DNSSEC, CAA or CSP headers.
- Lack of Secure or HttpOnly flags on non-sensitive cookies.
- Dead links.
- User enumeration.

## Known and documented behavior

These are described in the Supavisor documentation. Please check them before
reporting.

- **Pool modes.** Session mode and transaction mode share server connections
  differently. See the pool modes page in the documentation.
- **Upstream TLS** is configured per tenant, including the trusted CA used to
  verify the database certificate.

## Hosted vs. self-hosted

Supavisor is multi-tenant, so on the hosted platform crossing between tenants
is the most serious class of finding.

On a self-hosted pooler, the operator controls the tenants, the management
secrets and the network. We accept self-hosted findings when the shipped
defaults or the documented setup lead to the problem, and we treat them as
lower severity when the operator has to misconfigure the deployment first.
Label your report as described in the next section.

## How to write a report that gets triaged quickly

- **Say what you tested, at the top of the report and in the title.** Use one of
  these labels, for example `[Production] ...` in the title and a "Target" line
  at the start of the description:
  - **Production**: the hosted Supabase pooler, against projects you own.
    Include the project refs, the pooler host and whether you used session
    or transaction mode. Never test another customer's project.
  - **Self-hosted, default configuration**: the code in this repository run
    exactly as shipped or as our documentation describes, with no changed
    settings. Include the version, image tag or commit and how you started it.
  - **Self-hosted, custom configuration**: you changed settings, tenant
    configuration or code. List every setting you changed and why. We triage
    these lower unless the setting is one we recommend or document.

  Reports that do not say which of the three they are about are slower to
  triage, and are often closed with a request to retest. A finding that works
  only on a custom configuration is not a finding against production.

- **Test a real deployment.** Code reading alone is rarely enough. Static
  analysis findings need a working proof of concept against one of the targets
  above.
- **Give a short, runnable PoC.** The client and driver you used, the exact
  connection strings with secrets removed, the statements each client sent,
  and the output showing the impact.
- **State the attacker's starting position.** Which tenant and database user
  do they connect as, and what do they know? For management API findings,
  say which token, if any, you used.
- **Name the boundary you crossed.** Which tenant or database user could you
  not reach before? If both sides are the same user on the same tenant, say
  so.
- **Check the docs and this file first.** If the behavior is documented,
  explain why the documented design still fails.
- **Include versions.** The Supavisor version or commit, the pool mode, and
  the relevant tenant and TLS settings.
- **One issue per report.** Link variants of the same root cause instead of
  filing each variant separately.
- **Do not send unreviewed AI output.** Reports that were not reproduced by a
  human and that ignore the documentation are closed. AI-assisted analysis is
  fine when you have verified the result.
- **Respond to follow-up questions.** Reports that go quiet after we ask for a
  reproduction are closed.

## Severity

We rate severity by realistic impact on a default deployment. Crossing between
tenants or database users is rated highest. Issues that need an on-path
network position, an existing privilege, or an unusual configuration are
rated lower even when they are valid, and we may fix them as defense in
depth.

## Testing and disclosure

These are our program-wide rules. They also apply to AI agents and automated
tools acting on your behalf.

**Testing**

- Do not run automated scanners against other customers' projects. Scanners can
  run up costs for our users, can disrupt services, and our own security
  systems cannot tell hostile reconnaissance from research. If you want to run
  an automated scanner, notify security@supabase.com first and run it only on
  your own Supabase project.
- Do not attack projects that belong to other customers.
- Do not take advantage of a vulnerability you find, for example by downloading
  more data than necessary to demonstrate it, or by deleting or modifying other
  people's data.

**Disclosure**

- Do not reveal the problem to others until we have researched and fixed it and
  informed affected customers.
- If you want to share your research publicly (a conference, a blog or any
  other public forum), send us a draft for review and approval at least 30 days
  before the publication date. Do not include data about Supabase customer
  projects, customers' data, or information about Supabase employees,
  contractors or partners.

**What we promise**

- We will respond to your report within 5 business days with our evaluation and
  an expected resolution date.
- If you have followed these instructions, we will not take legal action against
  you in regard to the report.
- We will handle your report with strict confidentiality and will not pass on
  your personal details to third parties without your permission.
- We will keep you informed of our progress.
- In public information about the problem, we will name you as the discoverer
  unless you prefer otherwise.
