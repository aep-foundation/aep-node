# Example - Ephemeral AEP Platform

A small Express Platform for local examples. It publishes Platform discovery,
provisions Service-scoped Agent `did:web` identities, signs client assertions,
and performs hosted verification with in-memory stores. The example resolver
fetches `did:web` Service DID documents over HTTP before provisioning and
signing.

## Run

```bash
pnpm build
PORT=4100 pnpm start
```

The platform listens on `http://127.0.0.1:4100` by default.

The local example Service DID hosted by this Platform is:

```text
did:web:127.0.0.1%3A4100:services:example-service
```

Set `DID_HOST` when the DID host should differ from the host in `PUBLIC_BASE_URL`.
Protected Platform API routes expect `Authorization: Bearer demo-agent` by
default. Override that with `PLATFORM_AUTHORIZATION`.

The process logs real Platform operations when an Agent provisions an identity,
requests a delegated signature, or when a Service asks the Platform to verify a
client assertion.

## Example Shortcuts

The Platform uses in-memory stores, process-local ES256 keys, demo bearer
authorization, and localhost `did:web` hostnames. Agent identity ids,
idempotency keys, JWT `jti` values, and issued credential values are UUIDs.
Signing and verification still use real JWT and key algorithms.

| Endpoint                                                 | Purpose                                      |
| -------------------------------------------------------- | -------------------------------------------- |
| `GET /.well-known/aep-platform`                          | AEP Platform discovery document              |
| `GET /.well-known/did.json`                              | Platform `did:web` document                  |
| `GET /services/example-service/did.json`                 | Example Service `did:web` document           |
| `GET /agents/{agent_did_id}/did.json`                    | Service-scoped Agent `did:web` document      |
| `GET /v1/aep/agent-identities`                           | Lists provisioned Agent identities           |
| `POST /v1/aep/agent-identities`                          | Provisions a hosted Agent identity           |
| `GET /v1/aep/agent-identities/{agent_identity_id}`       | Returns one hosted Agent identity            |
| `PATCH /v1/aep/agent-identities/{agent_identity_id}`     | Updates hosted Agent identity lifecycle      |
| `POST /v1/aep/agent-identities/{agent_identity_id}/sign` | Returns a delegated AEP client assertion JWT |
| `POST /v1/aep/verifications`                             | Verifies a hosted client assertion           |

The private signing key stays inside this local Platform process. Agent examples
call the delegated signing endpoint for assertions.
