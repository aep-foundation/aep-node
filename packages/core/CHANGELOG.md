# @aep-foundation/core

## 0.7.0

### Minor Changes

- [#55](https://github.com/aep-foundation/aep-node/pull/55) [`22528ff`](https://github.com/aep-foundation/aep-node/commit/22528ffcfc6851a03ac64a2ef3d048b1d80bbbe4) Thanks [@zhoodar](https://github.com/zhoodar)! - Harden assertion verification, credential presentation, protected-resource URL binding,
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

## 0.6.0

### Minor Changes

- [#41](https://github.com/aep-foundation/aep-node/pull/41) [`6aadb9e`](https://github.com/aep-foundation/aep-node/commit/6aadb9ed25a5ac084ffc2c5be5161de1e30f92a1) Thanks [@nkavian](https://github.com/nkavian)! - Require stable Service-issued identifiers for built-in credentials, type per-grant-type Revoke capabilities, and remove every locally stored credential covered by a successful Revoke.

- [#49](https://github.com/aep-foundation/aep-node/pull/49) [`df158eb`](https://github.com/aep-foundation/aep-node/commit/df158eb98dca14a9b0242d15b82840bac39a402b) Thanks [@nkavian](https://github.com/nkavian)! - Move shared Platform client contracts and request builders into Core, remove the Agent package's dependency on the Platform implementation, and preserve Platform compatibility exports.

### Patch Changes

- [#40](https://github.com/aep-foundation/aep-node/pull/40) [`9af941c`](https://github.com/aep-foundation/aep-node/commit/9af941c948a4a4a5383960bb614f9ea4d126264d) Thanks [@nkavian](https://github.com/nkavian)! - Enforce the Core command idempotency header, Agent-and-key replay scope, and cross-command conflict behavior.

- [#43](https://github.com/aep-foundation/aep-node/pull/43) [`22422a5`](https://github.com/aep-foundation/aep-node/commit/22422a52fef708b957613bd13a9e506a4bf7f27a) Thanks [@nkavian](https://github.com/nkavian)! - Align Problem Details and Inspect validation with the Core protocol.

- [#44](https://github.com/aep-foundation/aep-node/pull/44) [`3ec9a20`](https://github.com/aep-foundation/aep-node/commit/3ec9a20217e23a755065091b20b7cfa285f2e6f0) Thanks [@nkavian](https://github.com/nkavian)! - Return the complete Service lifecycle vocabulary from Enroll when an existing enrollment is found.

- [#51](https://github.com/aep-foundation/aep-node/pull/51) [`fade141`](https://github.com/aep-foundation/aep-node/commit/fade141bd82125c2cb84f58265cd2758c28a0256) Thanks [@nkavian](https://github.com/nkavian)! - Refresh the Core runtime dependencies and synchronize the AEP conformance artifacts.

- [#38](https://github.com/aep-foundation/aep-node/pull/38) [`bb9e9a3`](https://github.com/aep-foundation/aep-node/commit/bb9e9a398a48f8e4d7cd3a607377bd5b9432b47a) Thanks [@nkavian](https://github.com/nkavian)! - Enforce the normative client-assertion JOSE header, Agent identity binding, lifetime, protected-resource URI, and HTTPS `did:web` resolution requirements.

## 0.5.1

### Patch Changes

- [#29](https://github.com/aep-foundation/aep-node/pull/29) [`5f1e0f0`](https://github.com/aep-foundation/aep-node/commit/5f1e0f0614d85de2388e3ec96b1e675b7dbfc33c) Thanks [@nkavian](https://github.com/nkavian)! - Align Inspect validation, generated schemas, conformance artifacts, endpoint defaults, and OpenAPI media-type handling with the published AEP drafts.

## 0.5.0

### Minor Changes

- [#24](https://github.com/aep-foundation/aep-node/pull/24) [`77daf0a`](https://github.com/aep-foundation/aep-node/commit/77daf0a6830aafeabcd14afd6efaccfdc88bad48) Thanks [@nkavian](https://github.com/nkavian)! - Use address-specific recipient names and `postcode` for postal addresses, support an optional third address line, and make the city optional.

## 0.4.0

### Minor Changes

- [#22](https://github.com/aep-foundation/aep-node/pull/22) [`6e252bb`](https://github.com/aep-foundation/aep-node/commit/6e252bb0a0f4c5700b989b43a0f3400bd76099e2) Thanks [@nkavian](https://github.com/nkavian)! - Accept missing and null Grant response scopes and normalize them to an empty array.

## 0.3.0

### Minor Changes

- [#14](https://github.com/aep-foundation/aep-node/pull/14) [`17ecb34`](https://github.com/aep-foundation/aep-node/commit/17ecb340fdd539f0ea6cf1494858f0beb3a0c7a2) Thanks [@nkavian](https://github.com/nkavian)! - Add AEP Claim Value catalog constants, types, schema metadata, validation and
  negotiation helpers, RFC 5321 mailbox validation, Agent and Service
  enforcement, Service resource limits, synced conformance artifacts, and
  conformance helper loaders.

## 0.2.0

### Minor Changes

- [#10](https://github.com/aep-foundation/aep-node/pull/10) [`6be44bd`](https://github.com/aep-foundation/aep-node/commit/6be44bdf75e685728d613b6fecfc5b11906617f7) Thanks [@nkavian](https://github.com/nkavian)! - Add cached public-document discovery, OpenAPI authentication policy interpretation, protected-resource fetch workflows, and authenticate assertion support.

- [#8](https://github.com/aep-foundation/aep-node/pull/8) [`18df20b`](https://github.com/aep-foundation/aep-node/commit/18df20b15fbb9c4a141375717e9651a0cdc222ab) Thanks [@nkavian](https://github.com/nkavian)! - Implement unified protected-resource authentication: the `authenticate` assertion operation and exact resource binding, Inspect authentication methods, SDK-owned credential validation and AEP challenges, bounded Agent probe/fetch orchestration, redirect and replay safety, credential cleanup and grant single-flight, and framework protected-resource adapters. Add generic pending Sign resolution across Grant and protected-resource authentication with opaque Platform context, stage-scoped idempotency, cancellation, and typed failures. Inspect caching honors HTTP freshness, supports conditional revalidation, and exposes persistent-cache integration. Also include bounded Inspect transport, Platform authentication headers and identity recovery, generalized Platform idempotency, lifecycle corrections, typed Revoke selectors, and expiration-aware credential selection.

  Allow Agent integrations to provide opaque initial Platform context for delegated signing, including automatically selected Grant types and requested scopes.

  Generalize public-document caching across Inspect, Platform Discovery, and OpenAPI with serializable caller storage and shared revalidation. Add finalized OpenAPI 3.1 advertisement validation, anonymous bounded retrieval, deterministic operation/security interpretation, and policy-aware protected-resource fetch. Grant now requires an existing identity and authoritative active Status before pending signing or credential issuance.

  Add the finalized dedicated protected-resource `AEP-Authorization` carrier
  across Core, Agent, Service, adapters, examples, and synchronized conformance
  artifacts while preserving standard-carrier and API-key behavior.

## 0.1.1

### Patch Changes

- [#5](https://github.com/aep-foundation/aep-node/pull/5) [`8b61426`](https://github.com/aep-foundation/aep-node/commit/8b614264648d29fb6c687d71477d1795d64f31f6) Thanks [@nkavian](https://github.com/nkavian)! - Publish consistent package homepage and repository metadata.

## 0.1.0

### Minor Changes

- [#1](https://github.com/aep-foundation/aep-node/pull/1) [`3d4713e`](https://github.com/aep-foundation/aep-node/commit/3d4713e2a9cf85478a415192c7c0abc90c374073) Thanks [@nkavian](https://github.com/nkavian)! - Add the initial AEP Node SDK packages, framework adapters, and conformance helpers.

## 0.0.0

Initial development version.
