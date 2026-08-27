# @aep-foundation/agent

Service references may be DIDs, hosts, host paths, or absolute resource URLs. `resolveServiceReference` derives a trusted origin, while `inspectService` applies bounded same-origin redirects, media-type validation, `did:web` Service-origin binding, abort support, and a one-mebibyte default response limit. A mismatch fails with `service_identity_mismatch` before the Agent provisions identity material, requests an assertion, or sends credentials.

Platform delegated signers return a `completed` or `pending` result. Pending results carry opaque `platformContext` and numeric `retryAfterSeconds`.

Agent-side workflows for AEP.

## Install

```sh
pnpm add @aep-foundation/agent
```

Use this package when your application acts as the Agent. It owns Service
discovery and AEP command transport; your application supplies identity
custody, persistence, and any user-approval experience required by the hosted
identity Platform.

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

## Enroll and Use a Service

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

Call `inspect()` before presenting capabilities to the Agent. `identity()`
returns the Service-scoped identity used by the remaining lifecycle commands.
`authenticationHeaders()` selects a usable stored credential or creates an
AEP client assertion when the Service supports assertion-only access.

Known Claim Values are validated before Enroll. If the Inspect document
advertises a required Claim Name that is absent from the submitted values,
Enroll throws `AepClaimRequirementsError` before sending the request. Unknown
preferred and optional Claim Names do not block enrollment.

To keep Grant and protected-resource fetch calls alive while delegated signing
is pending, configure a generic resolver. It receives the complete pending
result and a continuation that preserves its opaque Platform context:

```ts
const agent = createAepAgent({
  identityProvider,
  platformContextProvider: ({ command, grantType, requestedScopes }) =>
    command === "grant"
      ? {
          grant_type: grantType,
          ...(requestedScopes === undefined ? {} : { requested_scopes: requestedScopes })
        }
      : undefined,
  pendingSignResolver: async ({ continueSign, pending, signal }) => {
    await waitForExternalAuthorization(pending, { signal });

    for (;;) {
      const result = await continueSign();
      if (result.status === "completed") return result;
      await delay(result.retryAfterSeconds * 1_000, { signal });
    }
  }
});
```

`platformContextProvider` supplies opaque Platform-specific authorization context
before the initial Sign request. The Agent SDK does not interpret or sign the
returned object.

The first Sign request and its completion use different idempotency keys;
repeated `continueSign()` calls reuse the completion-stage key. Resolver errors
are exposed as `AepPendingSignResolverError`, including `code: "aborted"` for
cancellation. Without a resolver, pending signing continues to throw
`AepPendingSignError` so applications can manage continuation directly.

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

A Platform-backed application can recover a missing local identity reference
before provisioning:

```ts
const identity = await identityProvider.findIdentityByServiceDid(serviceDid);
```

The application uses the recovered identity to call Service Status and determine
whether the Service recognizes it.

## Storage Ports

The Agent engine can use application-provided stores:

- `AgentIdentityStore` persists the Service-scoped Agent identity.
- `AgentCredentialStore` persists issued session credentials.
- `AgentIdempotencyKeyProvider` creates command idempotency keys.
- `AepPublicDocumentCache` serializably caches validated Inspect, Platform
  Discovery, and OpenAPI documents across Agent and provider instances.

In-memory implementations are provided for examples and tests.

Production applications should provide durable stores scoped to the current
principal. If one process hosts multiple Agent principals, create one Agent
instance per principal or include the principal in every store lookup key.

Public documents default to a five-minute freshness window when the provider
does not supply HTTP cache directives. Inspect, Platform Discovery, and OpenAPI
documents use separate cache entries. Supply `AepPublicDocumentCache` when
validated documents must survive process restarts or be shared by Agent
instances.

Public-document requests allow at most five redirects, one mebibyte of decoded
response data, and 30 seconds of total completion time by default. The
low-level Inspect, Platform Discovery, and OpenAPI functions expose the
applicable response-size and timeout overrides.

## Low-Level Primitives

The package also exports low-level protocol primitives such as
`inspectService()`, `enrollService()`, `statusService()`, `grantService()`,
`revokeService()`, `discoverPlatform()`, `provisionPlatformIdentity()`,
`listPlatformIdentities()`, and `createPlatformDelegatedSigner()`.

These functions still own their AEP HTTP behavior. They use the runtime
`fetch()` implementation, validate responses, and return typed AEP results.

`createJwtClientAssertionSigner()` is the built-in `jose` signer adapter for
PEM, JWK, `CryptoKey`, `KeyObject`, and raw key material supported by `jose`.

`credentialPresentationHeaders()` turns built-in credentials into HTTP headers
for OAuth Bearer, API-key, and HTTP Basic presentation.

Pass `carrier: "dedicated"` to the presentation helpers, session
`authenticationHeaders()`, or `fetchProtectedResource()` to use
`AEP-Authorization` while preserving the `AEP`, `Bearer`, or `Basic` scheme.
The default remains `Authorization`. Dedicated mode can compose with unrelated
authentication through `additionalAuthenticationHeaders`; collisions with
SDK-controlled AEP fields are rejected.

`clientAssertionAuthenticationHeaders()` creates AEP JWT Authorization headers
for protected Service resources, and `protectedResourceAuthenticationHeaders()`
uses an issued built-in credential when one is available or falls back to AEP
JWT authentication.

`probeProtectedResource()` sends the caller's request anonymously and
classifies success, a valid AEP challenge, unrelated authentication, or another
HTTP response. `fetchProtectedResource()` performs bounded challenge-driven
discovery, credential selection or Grant, exact request replay, resource-bound
`authenticate` signing, redirect credential stripping, and cancellation. A
streaming body is rejected before authentication begins because it cannot be
replayed safely.

When Inspect advertises OpenAPI 3.1, `inspectOpenApiPolicy()` returns the
matched operation, policy source, public/required/fallback state, supported AEP
methods, freshness, and strict-slash suggestion. `fetchProtectedResource()`
uses a fresh definitive policy before challenge probing and retains live AEP
challenges as the fallback for stale, absent, unsupported, or contradictory
policy. Grant requires a previously stored or recoverable identity and a signed
active Status result before signing unless the same session has authoritative
active enrollment evidence.
