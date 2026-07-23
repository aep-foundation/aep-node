# Agent Enrollment Protocol for Node.js

[![CI](https://github.com/aep-foundation/aep-node/actions/workflows/ci.yml/badge.svg)](https://github.com/aep-foundation/aep-node/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/aep-foundation/aep-node/graph/badge.svg)](https://codecov.io/gh/aep-foundation/aep-node)
[![npm](https://img.shields.io/npm/v/@aep-foundation/agent?label=npm)](https://www.npmjs.com/package/@aep-foundation/agent)
[![node](https://img.shields.io/node/v/@aep-foundation/agent)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Official TypeScript SDKs for the
[Agent Enrollment Protocol](https://www.aep.foundation/)—the open protocol for
establishing trust between autonomous Agents and the Services they use.

AEP gives an Agent one interoperable lifecycle for discovering a Service,
enrolling a cryptographic identity, authenticating requests, receiving scoped
credentials, checking status, and revoking access.

```text
Agent                              Service
  │── Inspect ──────────────────────▶│  discover requirements and capabilities
  │── Enroll + identity proof ──────▶│  register the Agent
  │── Grant + proof-of-possession ──▶│  receive an optional scoped credential
  │── authenticated requests ───────▶│  use the Service
  │── Status / Revoke ──────────────▶│  manage the access lifecycle
```

## Start Here

Choose the side of the protocol you are building:

| I am building…                                  | Start with                                                        | What it provides                                                                                                    |
| ----------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| An Agent, CLI, worker, or automation runtime    | [`@aep-foundation/agent`](./packages/agent/README.md)             | Inspect, Enroll, Grant, Status, Revoke, credential storage, and protected-resource authentication                   |
| A Service that enrolls and authenticates Agents | [`@aep-foundation/service`](./packages/service/README.md)         | Protocol handlers, enrollment policy, credential issuance, replay protection, and protected-resource authentication |
| An Express, Fastify, Hono, or Next.js Service   | [Framework adapters](#framework-adapters)                         | Thin framework bindings over the Service SDK                                                                        |
| A hosted Agent identity Platform                | [`@aep-foundation/platform`](./packages/platform/README.md)       | Service-scoped `did:web` provisioning, delegated signing, verification, and lifecycle helpers                       |
| An AEP implementation or test suite             | [`@aep-foundation/conformance`](./packages/conformance/README.md) | Published schemas, test vectors, and conformance helpers                                                            |

All packages are ESM-first, support Node.js 22 or newer, publish under the
`@aep-foundation` npm scope, and include CommonJS entry points.

## Install

```sh
# Agent-side workflows
pnpm add @aep-foundation/agent

# Service core
pnpm add @aep-foundation/service

# Service on Express
pnpm add @aep-foundation/service @aep-foundation/express express
```

Use `npm install` or `yarn add` if those are the package managers in your
application.

## Protocol Surface

The SDK tracks the current
[AEP Internet-Draft set](https://github.com/aep-foundation/aep-specs):

| Command     | Purpose                                                                                 | Authentication       |
| ----------- | --------------------------------------------------------------------------------------- | -------------------- |
| **Inspect** | Discover the Service DID, endpoints, identity methods, grant types, and policy metadata | Public discovery     |
| **Enroll**  | Register a Service-scoped Agent identity                                                | AEP client assertion |
| **Grant**   | Exchange proof-of-possession for a scoped session credential                            | AEP client assertion |
| **Status**  | Read the Agent's current enrollment state and pending requirements                      | AEP client assertion |
| **Revoke**  | Invalidate an issued credential                                                         | AEP client assertion |

The baseline authentication method is `aep-jwt`. The current companion
packages and SDK surfaces support `did:web` identities plus OAuth Bearer,
API-key, and HTTP Basic session credentials. A Service can also use AEP client
assertions directly without issuing a session credential.

## Packages

### Protocol and workflows

| Package                                                                            | npm                                                                                                                                 | Role                                                                                     |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [`@aep-foundation/core`](./packages/core/README.md)                                | [![npm](https://img.shields.io/npm/v/@aep-foundation/core)](https://www.npmjs.com/package/@aep-foundation/core)                     | Wire types, constants, validators, signing helpers, and HTTP primitives                  |
| [`@aep-foundation/agent`](./packages/agent/README.md)                              | [![npm](https://img.shields.io/npm/v/@aep-foundation/agent)](https://www.npmjs.com/package/@aep-foundation/agent)                   | Agent-side discovery, enrollment, credentials, and lifecycle workflows                   |
| [`@aep-foundation/service`](./packages/service/README.md)                          | [![npm](https://img.shields.io/npm/v/@aep-foundation/service)](https://www.npmjs.com/package/@aep-foundation/service)               | Service-side protocol handling, policy hooks, persistence interfaces, and authentication |
| [`@aep-foundation/platform`](./packages/platform/README.md)                        | [![npm](https://img.shields.io/npm/v/@aep-foundation/platform)](https://www.npmjs.com/package/@aep-foundation/platform)             | Hosted Agent identity provisioning, delegated signing, and verification                  |
| [`@aep-foundation/conformance`](./packages/conformance/README.md)                  | [![npm](https://img.shields.io/npm/v/@aep-foundation/conformance)](https://www.npmjs.com/package/@aep-foundation/conformance)       | Schema and test-vector helpers for implementers                                          |
| [`@aep-foundation/service-policy`](./packages/extensions/service-policy/README.md) | [![npm](https://img.shields.io/npm/v/@aep-foundation/service-policy)](https://www.npmjs.com/package/@aep-foundation/service-policy) | Service Policy extension types and validation                                            |

### Framework adapters

The adapters mount the Service SDK's Inspect, Enroll, Grant, Revoke, and Status
handlers and can protect application routes with AEP authentication.

| Framework | Package                                                            | Example                                                           |
| --------- | ------------------------------------------------------------------ | ----------------------------------------------------------------- |
| Express   | [`@aep-foundation/express`](./packages/adapters/express/README.md) | [`aep-service-express`](./examples/aep-service-express/README.md) |
| Fastify   | [`@aep-foundation/fastify`](./packages/adapters/fastify/README.md) | [`aep-service-fastify`](./examples/aep-service-fastify/README.md) |
| Hono      | [`@aep-foundation/hono`](./packages/adapters/hono/README.md)       | [`aep-service-hono`](./examples/aep-service-hono/README.md)       |
| Next.js   | [`@aep-foundation/next`](./packages/adapters/next/README.md)       | [`aep-service-next`](./examples/aep-service-next/README.md)       |

## Runnable Flows

The examples are designed to run together: start the ephemeral Platform, start
a Service, then run an Agent against both.

| Layer             | Examples                                                                                                                                                                                                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Platform          | [`ephemeral did:web Platform`](./examples/aep-platform-ephemeral/README.md)                                                                                                                                                                                               |
| Services          | [`Express`](./examples/aep-service-express/README.md) · [`Fastify`](./examples/aep-service-fastify/README.md) · [`Hono`](./examples/aep-service-hono/README.md) · [`Next.js`](./examples/aep-service-next/README.md)                                                      |
| Credential grants | [`AEP JWT`](./examples/aep-service-credential-jwt/README.md) · [`OAuth Bearer`](./examples/aep-service-credential-oauth/README.md) · [`API key`](./examples/aep-service-credential-api-key/README.md) · [`HTTP Basic`](./examples/aep-service-credential-basic/README.md) |
| Agents            | [`Inspect`](./examples/aep-agent-did-web-inspect/README.md) · [`Enroll + Status`](./examples/aep-agent-did-web-enroll-status/README.md) · [`Grant + Status + Revoke`](./examples/aep-agent-did-web-grant-status-revoke/README.md)                                         |

Run the smallest end-to-end enrollment flow in three terminals:

```sh
# 1. Hosted identity Platform
pnpm --filter @aep-foundation/example-aep-platform-ephemeral build
pnpm --filter @aep-foundation/example-aep-platform-ephemeral start

# 2. Service
pnpm --filter @aep-foundation/example-aep-service-credential-jwt build
SERVICE_DID=did:web:127.0.0.1%3A4100:services:example-service \
  pnpm --filter @aep-foundation/example-aep-service-credential-jwt start

# 3. Agent
pnpm --filter @aep-foundation/example-aep-agent-did-web-enroll-status build
PLATFORM_URL=http://127.0.0.1:4100 \
SERVICE_URL=http://127.0.0.1:3000 \
  pnpm --filter @aep-foundation/example-aep-agent-did-web-enroll-status start
```

## Production Boundaries

The SDK deliberately keeps application policy and infrastructure visible.
Production deployments supply their own persistence, key custody,
authorization policy, idempotency and replay stores, and tenant boundaries.
See [INTEGRATION.md](./INTEGRATION.md) before moving beyond the in-memory
examples.

## Development

This is a pnpm and Turborepo monorepo. The merge gate is:

```sh
pnpm install
pnpm verify
```

For publish-surface changes, also run:

```sh
pnpm check-publish
```

For focused package work:

```sh
pnpm verify:pkg --filter=@aep-foundation/agent
```

See [DEVELOPMENT.md](./DEVELOPMENT.md) for the contributor workflow and the
[AEP specifications repository](https://github.com/aep-foundation/aep-specs)
for the normative drafts, schemas, examples, and test vectors.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting. The applications
under [`examples/`](https://github.com/aep-foundation/aep-node/tree/main/examples) are illustrative and use development-only
in-memory components.

## License

MIT.
