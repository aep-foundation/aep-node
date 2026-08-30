# @aep-foundation/service

Service-side workflows for AEP.

## Install

```sh
pnpm add @aep-foundation/service
```

Add one framework adapter when the Service uses Express, Fastify, Hono, or
Next.js. The Service package contains the protocol engine; adapters only bind
that engine to framework routes.

Protected-resource authentication selects `AEP-Authorization` when present and
otherwise accepts `Authorization`. Invalid dedicated fields and recognizable
AEP credentials in both fields fail closed as `not_recognized`; unrelated
`Authorization` schemes remain available to the application.

For production storage, idempotency, replay, and key-custody guidance, see the
repository [Integration Guide](../../INTEGRATION.md).

## What the Service Owns

- construct Inspect documents
- explicitly enable supported identity methods and grant types
- validate baseline AEP client assertions
- verify Platform-hosted client assertions through hosted verification endpoints
- handle Enroll and Status with pluggable enrollment persistence
- enforce POST command idempotency through pluggable command idempotency storage
- prevent client assertion replay through pluggable replay storage
- apply pluggable enrollment lifecycle policy
- dispatch Grant and Revoke requests to explicit grant type handlers
- produce AEP Problem Details responses
- provide built-in helpers for issuing and revoking standard session
  credentials through user-provided persistence

## Create a Service

```ts
import {
  apiKeyGrantType,
  authenticateProtectedResource,
  basicGrantType,
  createAepService,
  createDidWebClientAssertionVerifier,
  createHostedPlatformClientAssertionVerifier,
  createInMemoryCommandIdempotencyStore,
  createInMemoryEnrollmentStore,
  createInMemoryServiceCredentialStore,
  createStaticEnrollmentPolicy,
  createJwtClientAssertionVerifier,
  didWebIdentityMethod,
  storedOAuthBearerGrantType
} from "@aep-foundation/service";

const credentialStore = createInMemoryServiceCredentialStore();
const service = createAepService({
  serviceDid: "did:web:api.example.com",
  commandIdempotencyStore: createInMemoryCommandIdempotencyStore(),
  clientAssertionVerifier: createJwtClientAssertionVerifier({
    algorithms: ["ES256"],
    key: {
      format: "spki",
      pem: process.env.AEP_AGENT_PUBLIC_KEY_PEM!
    }
  }),
  enrollmentPolicy: createStaticEnrollmentPolicy({
    status: "active"
  }),
  enrollmentStore: createInMemoryEnrollmentStore(),
  identityMethods: [didWebIdentityMethod()],
  grantTypes: [
    storedOAuthBearerGrantType({
      store: credentialStore,
      issue: async (request) => ({
        access_token: await mintAccessToken(request),
        credential_id: crypto.randomUUID(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        scopes: request.requested_scopes ?? [],
        token_type: "Bearer"
      })
    }),
    apiKeyGrantType(),
    basicGrantType()
  ],
  claims: {
    required: ["contact.email"],
    limits: {
      maxEncodedBytes: 65_536,
      maxMemberCount: 128,
      maxObjectDepth: 8,
      maxStringLength: 4_096
    }
  }
});

const inspect = service.inspectDocument();

const enroll = await service.enroll(
  {
    agent_did: "did:web:agent.example.com:agents:123",
    claims: {
      "contact.email": "ops@example.com"
    },
    idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
  },
  {
    clientAssertion: "signed.jwt",
    idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
  }
);

const status = await service.status({
  clientAssertion: "signed.jwt"
});

const grant = await service.grant(
  {
    grant_type: "oauth-bearer"
  },
  {
    clientAssertion: "signed.jwt",
    idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-grant0000000"
  }
);

const revoke = await service.revoke(
  {
    grant_type: "oauth-bearer"
  },
  {
    clientAssertion: "signed.jwt",
    idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-revoke000000"
  }
);
```

The same `service` instance should serve `/.well-known/aep`, the advertised
command routes, and protected-resource authentication. Reusing the instance
keeps the Inspect document, enabled grant types, and authentication behavior
consistent.

For new enrollments, the Service validates known Claim Values and returns
`requirements_unmet` with `requirements_pending` when a Claim Name advertised
in `claims.required` is absent. Unknown submitted Claim Names and unknown
members of object-valued Claims are preserved for forward compatibility.
Before policy evaluation or storage, the Service also enforces Claim Value
resource limits. The values shown above are the secure defaults exported as
`DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS`; configure lower or higher positive
safe integers under `claims.limits` to match local policy. Member count covers
JSON object members across the Claims tree, object depth includes the top-level
Claims object, string length also applies to Claim Names and object member
names, and encoded size is the UTF-8 JSON size.

For Platform-hosted Agent identities, use hosted verification instead of local
DID resolution:

```ts
const hostedService = createAepService({
  serviceDid: "did:web:api.example.com",
  clientAssertionVerifier: createHostedPlatformClientAssertionVerifier({
    authorization: "Bearer service-platform-token",
    endpoint: "https://platform.example.com/v1/aep/verifications"
  }),
  identityMethods: [didWebIdentityMethod()]
});
```

Only explicitly enabled identity methods are advertised in `identity.methods`.
Only explicitly enabled grant types are advertised in `commands.grant_types` and
`commands.grant_types_config`. If no grant types are enabled, Grant and Revoke
are not listed in `commands.supported`.

`createAepService` accepts explicit implementation ports:

- `enrollmentStore` persists current Agent enrollment state.
- `commandIdempotencyStore` persists Enroll, Grant, and Revoke idempotency
  records and coordinates atomic command execution for each idempotency key.
- `replayStore` prevents client assertion `jti` replay.
- `enrollmentPolicy` decides the lifecycle state returned by Enroll.

Enroll and Status responses may independently include non-empty
`verification_pending` and `requirements_pending` arrays. Service responses
omit empty pending arrays and omit `owner_action_required` unless Owner action
is required.

In-memory implementations are provided for examples and tests. Production
Services should provide durable stores for enrollment state and command
idempotency, and an atomic replay store appropriate for the Service's
deployment.

## Minimum Integration

A Service integration needs to:

1. choose a stable Service DID bound to its public origin;
2. enable at least one identity method and client-assertion verifier;
3. provide durable enrollment, idempotency, and replay stores;
4. mount Inspect plus each advertised command route; and
5. call `authenticateProtectedResource()` before application authorization on
   protected routes.

Grant and Revoke are optional. Omit grant types when AEP client assertions are
sufficient for protected-resource access. The generated Inspect document then
omits those unsupported commands.

Authenticated command methods require `clientAssertion`. Services pass the
assertion to `clientAssertionVerifier`, then enforce baseline AEP claims for
audience, command, Agent identity, time window, TTL, and replay before invoking
command handlers.

`createJwtClientAssertionVerifier()` is the built-in `jose` verifier adapter for
PEM, JWK, `CryptoKey`, `KeyObject`, and raw key material supported by `jose`.
`createDidWebClientAssertionVerifier()` resolves DID-web public keys over HTTP
and verifies baseline AEP client assertion JWTs against the Service DID.
`createHostedPlatformClientAssertionVerifier()` posts the assertion to a
Platform hosted verification endpoint and lets the existing Service command
path enforce AEP audience, command, time window, TTL, and replay checks against
the returned claims. Hosted verification reuses a command's idempotency key
when one is available and otherwise uses the assertion `jti` as its stable
retry key.
`service.authenticateProtectedResource({ headers, method, url })` (or the
equivalent exported helper) authenticates protected resources independently of
authorization. Configure `authenticationMethods` in Service preference order.
Configure `openapi` to advertise a protected-resource OpenAPI 3.1 document and
its strict or equivalent trailing-slash matching mode through Inspect.
The result is either a normalized principal or an SDK-generated AEP challenge.
`aep-jwt` assertions must use `op: "authenticate"` and bind the exact resource
URL; command assertions are rejected. Built-in OAuth Bearer, Service-selected
API-key header, and Basic credentials are validated by their registered stored
grant handlers without returning credential secrets.

`storedOAuthBearerGrantType()`, `storedApiKeyGrantType()`, and
`storedBasicGrantType()` wrap issuer callbacks with built-in credential response
validation and persistence. Their Revoke handlers mark credentials revoked in
the configured `AepServiceCredentialStore`; `createInMemoryServiceCredentialStore()`
is provided for examples and tests. Custom grant handlers can implement the
same bounded `authenticate()` hook.
