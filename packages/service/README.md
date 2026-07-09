# @aep-foundation/service

Service-side workflows for AEP.

For production storage, idempotency, replay, and key-custody guidance, see the
repository [Integration Guide](../../INTEGRATION.md).

Initial responsibilities:

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

## Initial API

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
    required: ["contact.email"]
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

In-memory implementations are provided for examples and tests. Production
Services should provide durable stores for enrollment state and command
idempotency, and an atomic replay store appropriate for the Service's
deployment.

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
the returned claims.
`authenticateProtectedResource()` applies the same Status authentication path to
non-AEP resource endpoints that use AEP JWT Authorization.

`storedOAuthBearerGrantType()`, `storedApiKeyGrantType()`, and
`storedBasicGrantType()` wrap issuer callbacks with built-in credential response
validation and persistence. Their Revoke handlers mark credentials revoked in
the configured `AepServiceCredentialStore`; `createInMemoryServiceCredentialStore()`
is provided for examples and tests.
