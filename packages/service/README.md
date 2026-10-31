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
- verify `did:web` client assertions locally or through optional Platform hosted verification
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
import { randomBytes, randomUUID } from "node:crypto";

import {
  authenticateProtectedResource,
  createAepService,
  createDidWebClientAssertionVerifier,
  createHostedPlatformClientAssertionVerifier,
  createInMemoryCommandIdempotencyStore,
  createInMemoryEnrollmentStore,
  createInMemoryServiceCredentialStore,
  createStaticEnrollmentPolicy,
  didWebIdentityMethod,
  storedOAuthBearerGrantType
} from "@aep-foundation/service";

const credentialStore = createInMemoryServiceCredentialStore();
const service = createAepService({
  serviceDid: "did:web:api.example.com",
  commandIdempotencyStore: createInMemoryCommandIdempotencyStore(),
  clientAssertionVerifier: createDidWebClientAssertionVerifier(),
  authenticationMethods: ["oauth-bearer"],
  enrollmentPolicy: createStaticEnrollmentPolicy({
    status: "active"
  }),
  enrollmentStore: createInMemoryEnrollmentStore(),
  identityMethods: [didWebIdentityMethod()],
  grantTypes: [
    storedOAuthBearerGrantType({
      store: credentialStore,
      issue: async (request) => ({
        access_token: randomBytes(32).toString("base64url"),
        credential_id: randomUUID(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        scopes: request.requested_scopes ?? [],
        token_type: "Bearer"
      })
    })
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

For a Platform-hosted `did:web` identity, the Service can verify the published
DID document locally with `createDidWebClientAssertionVerifier()`. Hosted
verification is an optional alternative when the Service has a separate trust
relationship with the Platform:

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
  records for at least one hour and coordinates atomic command execution by
  Agent DID and idempotency key across all three commands.
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

## Credentials and Challenges

A few constraints the package enforces, worth knowing before you plug in your
own credential store:

- **`serviceDid` and `inspectUrl` end up in a `WWW-Authenticate` challenge**, so
  neither may contain a double quote, a backslash, or a control character. An
  Agent parses those parameters to decide where to enroll, and a value that
  escaped its quoted string could append a second `inspect` naming another
  origin. `createAepService` refuses such a value up front.
- **A protected-resource `url` must be absolute.** It becomes the `resource`
  claim the Agent's assertion is bound to, and it supplies the origin of the
  Inspect URL in a challenge.
- **Credential comparison is constant time**, and a request whose credentials
  match more than one stored record is refused unless every match names the
  same Agent and the same scopes. Presenting two valid API keys belonging to two
  different Agents authenticates as neither.

The stored grant handlers return the issued secret in the Grant response, but
pass only metadata and a salted verifier to `AepServiceCredentialStore`.
API keys and OAuth Bearer tokens use SHA-256 with a random 16-byte salt. Basic
credentials use asynchronous scrypt (`N=16384`, `r=8`, `p=1`) with a random
16-byte salt and a 32-byte output. The SDK compares verifier digests in constant time. Credential issuers
must generate secrets with the entropy required by their AEP grant profile.

`AepServiceCredentialRecord.credential` is an `AepStoredServiceCredential`:
it contains `credential_id`, `expires_at`, `scopes`, and `verifier.salt` and
`verifier.digest` as hexadecimal strings. It also contains `header` for an API
key, `username` for Basic, or `token_type: "Bearer"` for OAuth. It contains no
`api_key`, `password`, or `access_token`. Custom stores persist this record and
return it unchanged; the SDK performs verification and checks expiration and
revocation. `createInMemoryServiceCredentialStore` uses the same record format
and is suitable for examples and tests, not durable production storage.

The command idempotency store is separate: a cached successful Grant response
contains the issued secret so a retry can receive the same response. Protect
those cached responses as secrets, including encryption at rest, restricted
access, and retention controls. Do not log either issued credentials or cached
Grant responses.

## Upgrading credential storage from Service 0.3.4

Service 0.3.4 writes issued secrets into credential records. The stored grant handlers
accept those records as well as salted-verifier records, so existing credentials remain
usable with the same identifier, Agent, scopes, expiry, and revocation state. They do
not automatically rewrite your database during authentication.

Before deploying:

1. Update your `AepServiceCredentialStore` adapter to persist every field of
   `AepStoredServiceCredential`. A schema with mandatory `api_key`, `access_token`, or
   `password` columns must also allow records containing `verifier.salt` and
   `verifier.digest`. Keep existing records readable. Reads may return
   `AepLegacyServiceCredentialRecord` or `AepServiceCredentialRecord`.
2. Declare `readonly credentialFormat = "salted-verifier" as const` on the adapter
   only after implementing those writes. Missing this property causes a TypeScript
   error and a construction-time error in JavaScript, rather than an authentication
   failure for your customers.
3. Drain old Service workers before allowing the upgraded handlers to issue credentials
   or converting stored records. Service 0.3.4 cannot authenticate a verifier-only record;
   sharing new records with old workers is not a supported rolling deployment.
4. Optionally convert existing records with `await migrateServiceCredentialRecord(record)`.
   Write the result transactionally, preserving any concurrent revocation or other
   update. The helper returns a separate record and does not modify your database.
   Conversion avoids repeatedly deriving a verifier when an old record is authenticated.

Do not delete enrollment, credential, or command-idempotency records. Conversion does
not require the Agent to obtain a replacement credential. A rollback to 0.3.4 cannot
recover issued secrets from verifier records: retain a protected backup and plan the
deployment accordingly. This affects Service storage, not the Agent's wire credentials.

## Service Documents

For hosting, persistence, changed requirements, and integration checks, see the
[Service Documents integration guide](../../INTEGRATION.md#service-documents).

Set `serviceDocuments` on `createAepService()` to advertise the Service Documents
extension and its document catalog. An empty list enables the extension without
advertising documents. Omit the option for a Service without this extension.

```ts
serviceDocuments: [
  {
    id: "terms",
    type: "terms_of_service",
    title: "Terms of service",
    enrollment: "required",
    representations: [
      { media_type: "text/html", url: "https://example.com/terms" },
      { media_type: "application/json", url: "https://example.com/terms.json" }
    ]
  }
];
```

A catalog contains at most seven documents. IDs are case-sensitive, at most
32 ASCII letters, digits, periods, underscores or hyphens, starting with a
letter or digit. Every document needs an HTTPS HTML link. Types are open
strings; `AEP_SERVICE_DOCUMENT_TYPES` in the core package lists preferred types.
Use `enrollment: "not-required"` for documents that do not require acceptance.
The Service hosts portable JSON itself; the SDK does not publish document routes.

Enroll accepts an explicit `acknowledged_document_ids` declaration and echoes
only those IDs. Omission is not acceptance; an explicit empty list acknowledges
nothing. A declaration approved before another document was published is accepted
without silently adding that document. Grant returns HTTP 422 `requirements_unmet`
until current required documents and claims are satisfied. No credential is issued
with that error. The caller decides when to repeat Enroll, then request Grant again.

The enrollment store retains `acknowledgedDocumentIds` for declared IDs present
in the configured catalog. Unknown or retired IDs are echoed but do not grow the
stored list. A Service can set `requiredDocumentIds` on an existing enrollment to
require renewed acceptance of a currently advertised required document. Accepting
that ID clears its outstanding requirement. These fields contain IDs, not document
text, content versions, or evidence of reading.

An explicit repeated Enroll invokes `enrollmentPolicy.decideEnrollment(request,
{ now })`. Custom policies consult their own authoritative storage when a decision
depends on existing enrollment or account state. The SDK merges valid supplied
claims and acknowledgements; omitted values, original creation time,
lifecycle status and `since` are preserved. It does not reactivate suspended or
terminated enrollments or revoke credentials. Return `{ updateExisting: false }`
to return the enrollment unchanged, or `{ status: "rejected" }` to reject the
update without changing the record. The default policy accepts valid updates.

Policy decision fields `ownerActionRequired`, `requirementsPending`, and
`verificationPending` are optional. Omission preserves the stored value on a
repeat and defaults to `false` or an empty list on initial enrollment. Explicit
values replace stored values, including `false` and empty lists.

Custom stores keep the `findEnrollment`/`saveEnrollment` interface. Persist the
optional document fields when enabling this extension. Same-key retries replay
the original operation; distinct concurrent enrollment updates use ordinary
read/merge/save and can overwrite each other. Stronger concurrency protection is
a Service storage concern, not a required SDK interface.

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
`createDidWebClientAssertionVerifier()` resolves DID-web public keys over HTTPS
and verifies baseline AEP client assertion JWTs against the Service DID.
`createHostedPlatformClientAssertionVerifier()` posts the assertion to a
Platform hosted verification endpoint and lets the existing Service command
path enforce AEP audience, command, time window, TTL, and replay checks against
the returned claims. Hosted verification requires HTTPS, refuses redirects, and
uses a 30-second timeout (configurable with `timeoutMs`). Its idempotency key is
derived from the verification request body: retrying that exact request preserves
the key, while a command retry with a fresh assertion gets a separate verification.
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
is provided for examples and tests. These helpers advertise per-credential
Revoke because they support both targeted and grant-type Revoke. Custom grant
handlers can implement the same bounded `authenticate()` hook.

An `AepServiceCredentialStore` must reject a `credentialId` that the issuing
Service has assigned before, including identifiers issued to another Agent or
through another grant type. Revocation does not make an identifier reusable.
