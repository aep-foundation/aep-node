# @aep-foundation/agent

Service references may be DIDs, hosts, host paths, or absolute resource URLs. `resolveServiceReference` derives a trusted origin, while `inspectService` applies bounded same-origin redirects, media-type validation, abort support, and a one-mebibyte default response limit.

Platform delegated signers return a `completed` or `pending` result. Pending results carry opaque `platformContext` and numeric `retryAfterSeconds`; pass the returned context unchanged in a later signing call with a new idempotency key.

Agent-side workflows for AEP.

## Responsibilities

- fetch and validate Service Inspect documents from Service URLs
- construct AEP command URLs from Inspect HTTP metadata
- execute Enroll, Status, Grant, and Revoke over the AEP HTTP binding
- create baseline AEP client assertions
- use one pluggable Agent identity provider for Service-scoped identity and signing
- store Agent identities and issued session credentials through user-provided stores
- choose among advertised grant types
- create protected-resource authentication headers

The Agent package owns AEP network behavior. Applications provide storage and
identity custody; they do not provide custom Inspect or command transports.
For production storage and tenancy guidance, see the repository
[Integration Guide](../../INTEGRATION.md).

## High-Level API

```ts
import {
  createAepAgent,
  createInMemorySessionCredentialStore,
  createPlatformIdentityProvider
} from "@aep-foundation/agent";

const agent = createAepAgent({
  credentialStore: createInMemorySessionCredentialStore(),
  identityProvider: createPlatformIdentityProvider({
    authorization: "Bearer platform-api-token",
    platformUrl: "https://platform.example.com"
  })
});

const session = agent.serviceSession({
  serviceUrl: "https://api.example.com"
});

const inspect = await session.inspect();
const identity = await session.identity();

await session.enroll({
  claims: {
    "contact.email": "ops@example.com"
  }
});

const status = await session.status();

const grant = await session.grant({
  preferredGrantTypes: ["oauth-bearer", "api-key", "basic"],
  requestedScopes: ["read"]
});

const headers = await session.authenticationHeaders();

await session.revoke({
  credentialId: grant.body.credential_id
});
```

Platform authentication can use the compatibility `authorization` option or
caller-provided headers. The Platform defines its authentication header name:

```ts
const platformApiKeyHeader = platformConfiguration.apiKeyHeader;
const identityProvider = createPlatformIdentityProvider({
  authenticationHeaders: { [platformApiKeyHeader]: platformApiKey },
  platformUrl
});
```

For rotating bearer credentials, provide an async function. It is evaluated
for every Provision and Sign request:

```ts
const identityProvider = createPlatformIdentityProvider({
  authenticationHeaders: async () => ({
    Authorization: `Bearer ${await session.accessToken()}`
  }),
  platformUrl: inflowPlatformUrl
});
```

The SDK always controls `Accept`, `Content-Type`, and `Idempotency-Key`; values
for those names in caller-provided authentication headers are ignored.

`createAepAgent()` accepts exactly one `identityProvider`. Platform-hosted
`did:web` support is provided by `createPlatformIdentityProvider()`. Future
sovereign Agent support can implement the same `AgentIdentityProvider` interface
for local `did:key` or `did:jwk` custody without changing the Agent engine.

## Storage Ports

The Agent engine can use application-provided stores:

- `AgentIdentityStore` persists the Service-scoped Agent identity.
- `AgentCredentialStore` persists issued session credentials.
- `AgentIdempotencyKeyProvider` creates command idempotency keys.
- `AgentInspectCache` caches validated Inspect documents.

In-memory implementations are provided for examples and tests.

Production applications should provide durable stores scoped to the current
principal. If one process hosts multiple Agent principals, create one Agent
instance per principal or include the principal in every store lookup key.

## Low-Level Primitives

The package also exports low-level protocol primitives such as
`inspectService()`, `enrollService()`, `statusService()`, `grantService()`,
`revokeService()`, `discoverPlatform()`, `provisionPlatformIdentity()`, and
`createPlatformDelegatedSigner()`.

These functions still own their AEP HTTP behavior. They use the runtime
`fetch()` implementation, validate responses, and return typed AEP results.

`createJwtClientAssertionSigner()` is the built-in `jose` signer adapter for
PEM, JWK, `CryptoKey`, `KeyObject`, and raw key material supported by `jose`.

`credentialPresentationHeaders()` turns built-in credentials into HTTP headers
for OAuth Bearer, API-key, and HTTP Basic presentation.

`clientAssertionAuthenticationHeaders()` creates AEP JWT Authorization headers
for protected Service resources, and `protectedResourceAuthenticationHeaders()`
uses an issued built-in credential when one is available or falls back to AEP
JWT authentication.
