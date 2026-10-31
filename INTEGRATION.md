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
  idempotency. Its `executeIdempotentCommand()` implementation must atomically
  scope records by Agent DID and idempotency key across all three commands,
  bind the command and request hash, and retain replayable responses for at
  least one hour.
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

The store must ensure that concurrent matching requests for the same Agent and
idempotency key execute the command body at most once. Later matching requests
must replay the stored response. Reuse by that Agent for another command or
request body must return an idempotency conflict.

`AepClientAssertionReplayStore.consumeReplay()` must also be atomic. Two
concurrent requests with the same Agent DID and `jti` must not both succeed.

## Service Documents

The Service owns its document catalog, acceptance records, and decisions about
changed requirements. The Agent presents documents and submits only the IDs
covered by the Owner's affirmative decision. A Platform can mediate that decision;
it does not decide whether a Service must notify users or require acceptance again.

1. Configure `createAepService({ serviceDocuments: [...] })` using the
   [Service package example](packages/service/README.md#service-documents).
   Each descriptor needs a stable ID, title, open document type, `required` or
   `not-required`, and an HTML reading link. The catalog allows seven documents
   with IDs of at most 32 characters.
2. Host the HTML anonymously. Portable JSON is optional and must contain the full
   document; its Service-authored summary is optional. Follow the
   [portable document schema](https://github.com/aep-foundation/aep-specs/blob/main/ietf/schemas/portable-service-document.schema.json).
   The SDK advertises representations but does not host them.
3. Persist `acknowledgedDocumentIds` and `requiredDocumentIds` in the Service's
   enrollment store. The SDK merges accepted IDs and supplied claims during an
   accepted repeated Enroll. Omitted claims remain; supplied values replace the
   corresponding stored values. The response echoes this operation's declaration,
   not the cumulative stored list.
4. Decide how changes affect existing users. Editing text under an existing ID
   does not itself require another acceptance. To require it, put that advertised
   required ID in the enrollment's `requiredDocumentIds`. A newly advertised
   required ID that has not been accepted also blocks Grant. The Service owns any
   notification and updates to its authoritative records.

Grant returns HTTP 422 `requirements_unmet` before issuing a credential when
required claims or documents remain unmet. `requirements_pending` names missing
claims and includes `service_documents` for documents; `required_document_ids`
lists the missing document IDs. Agents present those requirements and direct the
Owner through an explicit Enroll. A later Grant is a separate caller decision.
Use a new idempotency key for each explicit update; retry the same operation with
its original key. See [Agent presentation and acknowledgement](packages/agent/README.md#service-documents).

Grant enforcement does not revoke existing credentials or replace application
authorization on protected resources. Services that allow direct AEP client
assertion access, or require immediate enforcement for existing credentials,
must apply their requirements policy in that application authorization layer.

Validate the integration with these cases:

- No documents: omit `serviceDocuments`; ordinary enrollment remains available.
- Only `not-required` documents: show reading links without requiring acceptance.
- Required documents on initial enrollment: absent acknowledgement fails; an approved declaration is
  echoed and stored without adding IDs the Owner did not accept.
- Requirements change during approval: accept the valid earlier declaration;
  a later Grant reports the remaining requirement without issuing a credential.
- Explicit recovery: Enroll with the approved IDs and missing claims, preserving
  identity and prior accepted information; request Grant separately afterward.

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

`PlatformIdempotencyStore.execute()` coordinates the full lookup, conflict check,
callback execution, and persistence atomically for each authenticated principal
and key. Use shared transactional storage or equivalent coordination across
workers. Exact retries return the stored record; changed operations or request
fingerprints return a conflict. Keep records until their supplied `expiresAt`.
Authenticate the request before constructing its stable `subject`; the Platform
also calls the authorizer before replaying a stored result.

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
- `InMemoryManagedAgentRegistry` and `createInMemoryPlatformIdempotencyStore()`
  from `@aep-foundation/platform`

Do not use these helpers for production data. They are process-local, volatile,
and do not provide cross-process durability.
