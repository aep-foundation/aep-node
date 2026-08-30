# AEP Node Integration Guide

This guide describes the package boundaries an application integrator must own
when moving beyond the in-memory examples.

## Package Boundaries

The SDK packages implement AEP protocol behavior. Integrators own product
storage, tenancy, authorization, key custody, observability, and HTTP hosting.

- `@aep-foundation/agent` owns Agent-side AEP network flows. It fetches Inspect
  documents, provisions or retrieves Service-scoped Agent identity through an
  identity provider, signs authenticated commands, chooses grant types, stores
  issued credentials, and builds protected-resource authentication headers.
- `@aep-foundation/service` owns Service-side AEP command handling. It validates
  Inspect, Enroll, Status, Grant, Revoke, client assertions, replay, command
  idempotency, enrollment lifecycle, and credential issuance/revocation through
  explicit ports.
- `@aep-foundation/platform` owns hosted Agent identity protocol helpers. It
  builds discovery, provisions Service-scoped Agent identities, signs delegated
  client assertions, verifies hosted assertions, and exposes lifecycle behavior
  through explicit ports.

The packages intentionally do not implement production databases, distributed
caches, key management systems, account models, or authorization policy.

## Agent Integration

Create one Agent instance per principal boundary, or provide stores that are
already scoped by principal. The default Agent stores are keyed by Service DID
and are appropriate for tests, examples, and single-principal processes.

For a multi-tenant application, the integrator should scope all Agent stores by
the current account, user, workspace, tenant, or equivalent product principal.
Common approaches are:

- create one `createAepAgent()` instance per principal with stores bound to that
  principal
- create shared store implementations that include the principal in every lookup
  key

Production Agent integrations should provide:

- `AgentIdentityStore` for Service-scoped Agent identity records
- `AgentCredentialStore` for issued session credentials
- `AgentInspectCache` for validated Inspect documents
- `AgentIdempotencyKeyProvider` for deterministic or random command
  idempotency keys
- one `AgentIdentityProvider` that handles the supported identity custody modes

The Agent package owns AEP HTTP behavior. Do not replace Inspect or command
transport with application callbacks; pass Service and Platform URLs to the
Agent APIs.

## Service Integration

Production Services should pass explicit implementations for all Service state
ports. The in-memory implementations exist for examples and tests.

- `AepEnrollmentStore` persists Agent enrollment state and should be keyed by
  Agent DID within the Service's product boundary.
- `AepEnrollmentPolicy` decides whether an Enroll request becomes active,
  pending, suspended, or rejected according to product policy.
- `AepCommandIdempotencyStore` coordinates Enroll, Grant, and Revoke
  idempotency. Its `executeIdempotentCommand()` implementation must be atomic
  for a given command key.
- `AepClientAssertionReplayStore` prevents accepted client assertion `jti`
  replay until the assertion replay window expires.
- `AepServiceCredentialStore` persists issued built-in credentials when using
  `storedOAuthBearerGrantType()`, `storedApiKeyGrantType()`, or
  `storedBasicGrantType()`.

`AepCommandIdempotencyStore.executeIdempotentCommand()` should use the
application's strongest available concurrency primitive. Suitable production
implementations include a serializable database transaction, a conditional
insert with row locking, an advisory lock, or a distributed cache lock backed by
durable response storage.

The store must ensure that concurrent matching requests for the same
idempotency key execute the command body at most once. Later matching requests
must replay the stored response. Later conflicting requests must return an
idempotency conflict.

`AepClientAssertionReplayStore.consumeReplay()` must also be atomic. Two
concurrent requests with the same Agent DID and `jti` must not both succeed.

## Platform Integration

Production Platforms should pass explicit implementations for all Platform
state, authorization, and key custody ports:

- `PlatformIdentityStore` for managed Agent identity records
- `PlatformIdempotencyStore` for provision, delegated-signing, and hosted-verification idempotency
- `PlatformReplayStore` for delegated client assertion replay checks
- `PlatformKeyStore` for signing keys and public DID document material
- `PlatformServiceDidResolver` for Service DID authorization and resolution
- `PlatformAuthorizer` for product authorization
- `PlatformLifecyclePolicy` for identity lifecycle transitions

Key custody is an application concern. A production Platform should use a KMS,
HSM, cloud key service, or equivalent product-approved custody layer rather
than keeping private signing keys in process memory.

## In-Memory Helpers

In-memory helpers are intentionally exported because they keep examples and
tests small:

- `createInMemoryAgentIdentityStore()`
- `createInMemorySessionCredentialStore()`
- `createInMemoryInspectCache()`
- `createInMemoryEnrollmentStore()`
- `createInMemoryCommandIdempotencyStore()`
- `createInMemoryClientAssertionReplayStore()`
- `createInMemoryServiceCredentialStore()`
- Platform memory stores exported by `@aep-foundation/platform`

Do not use these helpers for production data. They are process-local, volatile,
and do not provide cross-process durability.
