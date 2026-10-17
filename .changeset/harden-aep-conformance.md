---
"@aep-foundation/agent": minor
"@aep-foundation/conformance": minor
"@aep-foundation/core": minor
"@aep-foundation/express": minor
"@aep-foundation/fastify": minor
"@aep-foundation/hono": minor
"@aep-foundation/next": minor
"@aep-foundation/platform": minor
"@aep-foundation/service": minor
---

Harden assertion verification, credential presentation, protected-resource URL binding,
DID resolution, and Platform request validation. Extend conformance artifact validation
and improve package test coverage.

Core removes the optional `type` override from `createProblemDetails` and the optional
`typ` property from assertion signing options. Problem types are derived from the error
code and assertion headers use `JWT`. Platform verification reasons are restricted to
`verified` and `not_recognized`, consistent with the verification result.

Service credential stores persist metadata and salted verifiers instead of issued
secrets. Custom stores must adopt `AepStoredServiceCredential` and acknowledge verifier
writes with `credentialFormat`. Existing raw-secret records remain readable and can be
converted with `migrateServiceCredentialRecord` without reissuance. Drain old Service
workers before writing verifier-only records; see the Service storage upgrade guide.
Grant responses retain
their wire format. Enforce advertised identity methods, honor Inspect freshness
within sessions, validate Platform assertion issuance time, and accept valid
authentication-scheme spacing.

Verify PEM keys using the assertion's allowed algorithm rather than allowlist order,
and preserve encoded DID path segments during resolution.

Expose authenticated principals to adapter callbacks, continue Hono middleware after
authentication, and preserve double-slash request paths in resource binding. Correct
Express and Fastify parser examples for AEP media types and malformed request bodies.

Constrain Platform credentials to their configured origin and reject authenticated
redirects. Honor Platform discovery freshness, require a fresh challenge after
cross-origin resource redirects, and restrict credential selection to the resource's
permitted methods. Keep independent Grant requests separate and wait for credential
persistence before completing shared requests. Accept challenge parameter whitespace,
forward pending-sign resolvers across lifecycle commands, and correct the revocation example.

Require complete test-vector metadata and matching artifact paths. Exercise Agent
redirect credential isolation, assertion rebinding, authentication failure responses,
and Inspect and Platform discovery caching through the conformance adapter.

Replace Platform idempotency store `get`/`set` with atomic `execute`; custom stores
must coordinate matching concurrent requests and persist the callback result.
Retain existing results and compare the optional canonical fingerprint when both
records contain it, falling back to the compatible fingerprint otherwise. See the
Platform storage upgrade guide for coordination and locale requirements.
Reauthorize cached retries, reject invalid lifetime strings and local-limit violations,
enforce active identity state and bare-DID hosted verification, and validate DID URL
configuration. Correct the Platform example and integration documentation.

Separate hosted verification retry keys from command retry keys, require HTTPS,
refuse redirects, and bound verification requests. Restrict JWT verification to
advertised algorithms, preserve protected-resource discovery challenges, report
unsupported authentication methods and inactive enrollment states accurately,
and validate issued API-key headers before persistence. Snapshot authentication
configuration and correct the Service example.
