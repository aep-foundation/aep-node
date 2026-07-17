---
"@aep-foundation/agent": minor
"@aep-foundation/conformance": minor
"@aep-foundation/core": minor
"@aep-foundation/platform": minor
"@aep-foundation/service": minor
"@aep-foundation/express": patch
"@aep-foundation/fastify": patch
"@aep-foundation/hono": patch
"@aep-foundation/next": patch
---

Implement unified protected-resource authentication: the `authenticate` assertion operation and exact resource binding, Inspect authentication methods, SDK-owned credential validation and AEP challenges, bounded Agent probe/fetch orchestration, redirect and replay safety, credential cleanup and grant single-flight, and framework protected-resource adapters. Add generic pending Sign resolution across Grant and protected-resource authentication with opaque Platform context, stage-scoped idempotency, cancellation, and typed failures. Inspect caching honors HTTP freshness, supports conditional revalidation, and exposes persistent-cache integration. Also include bounded Inspect transport, Platform authentication headers and identity recovery, generalized Platform idempotency, lifecycle corrections, typed Revoke selectors, and expiration-aware credential selection.

Allow Agent integrations to provide opaque initial Platform context for delegated signing, including automatically selected Grant types and requested scopes.

Generalize public-document caching across Inspect, Platform Discovery, and OpenAPI with serializable caller storage and shared revalidation. Add finalized OpenAPI 3.1 advertisement validation, anonymous bounded retrieval, deterministic operation/security interpretation, and policy-aware protected-resource fetch. Grant now requires an existing identity and authoritative active Status before pending signing or credential issuance.

Add the finalized dedicated protected-resource `AEP-Authorization` carrier
across Core, Agent, Service, adapters, examples, and synchronized conformance
artifacts while preserving standard-carrier and API-key behavior.
