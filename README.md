# Agent Enrollment Protocol

[![ci](https://github.com/aep-foundation/aep-node/actions/workflows/ci.yml/badge.svg)](https://github.com/aep-foundation/aep-node/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/aep-foundation/aep-node/graph/badge.svg)](https://codecov.io/gh/aep-foundation/aep-node)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Public TypeScript SDK packages for the
[Agent Enrollment Protocol](https://www.aep.foundation/).

Agent Enrollment Protocol helps Agents enroll with Services, authenticate their
identity, receive scoped credentials, and manage the lifecycle of that access
through protocol-defined HTTP flows.

This repository is the AEP Foundation's TypeScript implementation of the
current AEP Internet-Draft set:

- Core AEP HTTP binding: Inspect, Enroll, Grant, Revoke, and Status.
- Baseline client assertion authentication.
- Identity method registration, including the optional `did:web` method.
- Optional grant types: OAuth Bearer, API-key, and HTTP Basic.
- Agent, Service, Platform, adapter, and conformance-facing package surfaces.

## Who This Is For

- Agent builders integrating AEP enrollment into clients, CLIs, workers, or
  automation runtimes.
- Service builders exposing AEP enrollment and credential issuance beside their
  own protected APIs.
- Platform builders hosting `did:web` Agent identity provisioning and signing
  workflows.
- Implementers validating behavior against published schemas, examples, and
  test vectors.

## Status

This repository contains the initial public SDK package surfaces for AEP core
wire types, Agent workflows, Service workflows, Platform-hosted identity
workflows, framework adapters, and conformance fixtures synced from
`aep-specs`.

The packages are published under the `@aep-foundation/*` npm scope and are
designed so production persistence, key custody, authorization policy, and
multi-tenant boundaries remain explicit integrator concerns.

## Packages

```text
packages/
  adapters/
    express/
    fastify/
    hono/
    next/
  agent/
  conformance/
  core/
  extensions/
    service-policy/
  platform/
  service/
```

Primary package surfaces:

- `@aep-foundation/core` - protocol types, validators, signing helpers, and HTTP
  binding primitives.
- `@aep-foundation/agent` - Agent-side inspect, enrollment, status, grant,
  revoke, and decommission workflows.
- `@aep-foundation/service` - Service-side protocol handling and extension
  registration.
- `@aep-foundation/platform` - Platform-hosted `did:web` identity provisioning
  and signing helpers.
- `@aep-foundation/conformance` - schema and test-vector helpers for SDKs and
  downstream implementations.
- `@aep-foundation/express`, `@aep-foundation/fastify`,
  `@aep-foundation/hono`, and `@aep-foundation/next` - framework adapters for
  mounting Service routes.
- `@aep-foundation/service-policy` - Service policy extension helpers.

## Development

This project uses pnpm, Turborepo, tsup, Vitest, TypeScript strict mode,
TypeDoc, and Changesets.

```sh
pnpm install
pnpm build
pnpm typecheck
pnpm test
pnpm lint
pnpm typedoc
pnpm smoke:examples
```

For focused package work, use Turbo-backed filters so changed workspace
dependencies are rebuilt before the target package runs:

```sh
pnpm verify:pkg --filter=@aep-foundation/agent
```

See [DEVELOPMENT.md](./DEVELOPMENT.md) for the focused workflow details.
See [INTEGRATION.md](./INTEGRATION.md) for production integration guidance on
storage, idempotency, replay, key custody, and multi-tenant Agent scoping.

## Specification Source

Protocol behavior should track the current AEP Internet-Draft set and the
published schemas and test vectors from `aep-specs`.

Conformance fixtures are synced from a local `aep-specs` checkout:

```sh
pnpm sync:spec-artifacts
```

By default, the sync command reads `../aep-specs/ietf`. Set `AEP_SPECS_DIR` to
override the source checkout.

## Examples

Runnable examples live under `examples/`:

- `@aep-foundation/example-aep-platform-ephemeral`
- `@aep-foundation/example-aep-service-express`
- `@aep-foundation/example-aep-service-fastify`
- `@aep-foundation/example-aep-service-hono`
- `@aep-foundation/example-aep-service-next`
- `@aep-foundation/example-aep-service-credential-jwt`
- `@aep-foundation/example-aep-service-credential-api-key`
- `@aep-foundation/example-aep-service-credential-basic`
- `@aep-foundation/example-aep-service-credential-oauth`
- `@aep-foundation/example-aep-agent-did-web-inspect`
- `@aep-foundation/example-aep-agent-did-web-enroll-status`
- `@aep-foundation/example-aep-agent-did-web-grant-status-revoke`

To run the simplest end-to-end flow, start the Platform, start one Service, and
then run an Agent:

```sh
pnpm --filter @aep-foundation/example-aep-platform-ephemeral build
pnpm --filter @aep-foundation/example-aep-platform-ephemeral start

pnpm --filter @aep-foundation/example-aep-service-credential-jwt build
SERVICE_DID=did:web:127.0.0.1%3A4100:services:example-service \
  pnpm --filter @aep-foundation/example-aep-service-credential-jwt start

pnpm --filter @aep-foundation/example-aep-agent-did-web-enroll-status build
PLATFORM_URL=http://127.0.0.1:4100 \
SERVICE_URL=http://127.0.0.1:3000 \
  pnpm --filter @aep-foundation/example-aep-agent-did-web-enroll-status start
```

## License

MIT
