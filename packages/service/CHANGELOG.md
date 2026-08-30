# @aep-foundation/service

## 0.3.3

### Patch Changes

- [#35](https://github.com/aep-foundation/aep-node/pull/35) [`0946834`](https://github.com/aep-foundation/aep-node/commit/0946834d876e08af2c8455437ff8b6dda1f31c4d) Thanks [@nkavian](https://github.com/nkavian)! - Preserve pending enrollment details in Grant errors and send stable idempotency keys with hosted Platform verification requests.

## 0.3.2

### Patch Changes

- Updated dependencies [[`77daf0a`](https://github.com/aep-foundation/aep-node/commit/77daf0a6830aafeabcd14afd6efaccfdc88bad48)]:
  - @aep-foundation/core@0.5.0

## 0.3.1

### Patch Changes

- Updated dependencies [[`6e252bb`](https://github.com/aep-foundation/aep-node/commit/6e252bb0a0f4c5700b989b43a0f3400bd76099e2)]:
  - @aep-foundation/core@0.4.0

## 0.3.0

### Minor Changes

- [#14](https://github.com/aep-foundation/aep-node/pull/14) [`17ecb34`](https://github.com/aep-foundation/aep-node/commit/17ecb340fdd539f0ea6cf1494858f0beb3a0c7a2) Thanks [@nkavian](https://github.com/nkavian)! - Add AEP Claim Value catalog constants, types, schema metadata, validation and
  negotiation helpers, RFC 5321 mailbox validation, Agent and Service
  enforcement, Service resource limits, synced conformance artifacts, and
  conformance helper loaders.

### Patch Changes

- Updated dependencies [[`17ecb34`](https://github.com/aep-foundation/aep-node/commit/17ecb340fdd539f0ea6cf1494858f0beb3a0c7a2)]:
  - @aep-foundation/core@0.3.0

## 0.2.0

### Minor Changes

- [#8](https://github.com/aep-foundation/aep-node/pull/8) [`18df20b`](https://github.com/aep-foundation/aep-node/commit/18df20b15fbb9c4a141375717e9651a0cdc222ab) Thanks [@nkavian](https://github.com/nkavian)! - Implement unified protected-resource authentication: the `authenticate` assertion operation and exact resource binding, Inspect authentication methods, SDK-owned credential validation and AEP challenges, bounded Agent probe/fetch orchestration, redirect and replay safety, credential cleanup and grant single-flight, and framework protected-resource adapters. Add generic pending Sign resolution across Grant and protected-resource authentication with opaque Platform context, stage-scoped idempotency, cancellation, and typed failures. Inspect caching honors HTTP freshness, supports conditional revalidation, and exposes persistent-cache integration. Also include bounded Inspect transport, Platform authentication headers and identity recovery, generalized Platform idempotency, lifecycle corrections, typed Revoke selectors, and expiration-aware credential selection.

  Allow Agent integrations to provide opaque initial Platform context for delegated signing, including automatically selected Grant types and requested scopes.

  Generalize public-document caching across Inspect, Platform Discovery, and OpenAPI with serializable caller storage and shared revalidation. Add finalized OpenAPI 3.1 advertisement validation, anonymous bounded retrieval, deterministic operation/security interpretation, and policy-aware protected-resource fetch. Grant now requires an existing identity and authoritative active Status before pending signing or credential issuance.

  Add the finalized dedicated protected-resource `AEP-Authorization` carrier
  across Core, Agent, Service, adapters, examples, and synchronized conformance
  artifacts while preserving standard-carrier and API-key behavior.

- [#11](https://github.com/aep-foundation/aep-node/pull/11) [`2b05290`](https://github.com/aep-foundation/aep-node/commit/2b052908ca238d591c74ef6b531cfe29ae85b126) Thanks [@nkavian](https://github.com/nkavian)! - Add generic protected-resource authentication to the Service SDK and framework adapters, including standard and dedicated authorization carriers.

### Patch Changes

- Updated dependencies [[`6be44bd`](https://github.com/aep-foundation/aep-node/commit/6be44bdf75e685728d613b6fecfc5b11906617f7), [`18df20b`](https://github.com/aep-foundation/aep-node/commit/18df20b15fbb9c4a141375717e9651a0cdc222ab)]:
  - @aep-foundation/core@0.2.0

## 0.1.1

### Patch Changes

- [#5](https://github.com/aep-foundation/aep-node/pull/5) [`8b61426`](https://github.com/aep-foundation/aep-node/commit/8b614264648d29fb6c687d71477d1795d64f31f6) Thanks [@nkavian](https://github.com/nkavian)! - Publish consistent package homepage and repository metadata.

- Updated dependencies [[`8b61426`](https://github.com/aep-foundation/aep-node/commit/8b614264648d29fb6c687d71477d1795d64f31f6)]:
  - @aep-foundation/core@0.1.1

## 0.1.0

### Minor Changes

- [#1](https://github.com/aep-foundation/aep-node/pull/1) [`3d4713e`](https://github.com/aep-foundation/aep-node/commit/3d4713e2a9cf85478a415192c7c0abc90c374073) Thanks [@nkavian](https://github.com/nkavian)! - Add the initial AEP Node SDK packages, framework adapters, and conformance helpers.

### Patch Changes

- Updated dependencies [[`3d4713e`](https://github.com/aep-foundation/aep-node/commit/3d4713e2a9cf85478a415192c7c0abc90c374073)]:
  - @aep-foundation/core@0.1.0

## 0.0.0

Initial development version.
