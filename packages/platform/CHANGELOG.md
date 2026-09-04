# @aep-foundation/platform

## 0.3.0

### Minor Changes

- [#42](https://github.com/aep-foundation/aep-node/pull/42) [`4064f3c`](https://github.com/aep-foundation/aep-node/commit/4064f3cedf93ced6080297988f1fabb9999a6fd5) Thanks [@nkavian](https://github.com/nkavian)! - Require advertised protected-resource authentication methods and explicit operation-aware Platform authorization.

### Patch Changes

- [#49](https://github.com/aep-foundation/aep-node/pull/49) [`df158eb`](https://github.com/aep-foundation/aep-node/commit/df158eb98dca14a9b0242d15b82840bac39a402b) Thanks [@nkavian](https://github.com/nkavian)! - Move shared Platform client contracts and request builders into Core, remove the Agent package's dependency on the Platform implementation, and preserve Platform compatibility exports.

- [#38](https://github.com/aep-foundation/aep-node/pull/38) [`bb9e9a3`](https://github.com/aep-foundation/aep-node/commit/bb9e9a398a48f8e4d7cd3a607377bd5b9432b47a) Thanks [@nkavian](https://github.com/nkavian)! - Enforce the normative client-assertion JOSE header, Agent identity binding, lifetime, protected-resource URI, and HTTPS `did:web` resolution requirements.

- [#48](https://github.com/aep-foundation/aep-node/pull/48) [`030cf0e`](https://github.com/aep-foundation/aep-node/commit/030cf0e6233af36ad7e917f8a8528389de7b2a32) Thanks [@nkavian](https://github.com/nkavian)! - Reject invalid Platform identity-list pagination metadata and prevent Platform producers from constructing invalid totals.

- Updated dependencies [[`6aadb9e`](https://github.com/aep-foundation/aep-node/commit/6aadb9ed25a5ac084ffc2c5be5161de1e30f92a1), [`9af941c`](https://github.com/aep-foundation/aep-node/commit/9af941c948a4a4a5383960bb614f9ea4d126264d), [`22422a5`](https://github.com/aep-foundation/aep-node/commit/22422a52fef708b957613bd13a9e506a4bf7f27a), [`df158eb`](https://github.com/aep-foundation/aep-node/commit/df158eb98dca14a9b0242d15b82840bac39a402b), [`3ec9a20`](https://github.com/aep-foundation/aep-node/commit/3ec9a20217e23a755065091b20b7cfa285f2e6f0), [`fade141`](https://github.com/aep-foundation/aep-node/commit/fade141bd82125c2cb84f58265cd2758c28a0256), [`bb9e9a3`](https://github.com/aep-foundation/aep-node/commit/bb9e9a398a48f8e4d7cd3a607377bd5b9432b47a)]:
  - @aep-foundation/core@0.6.0

## 0.2.5

### Patch Changes

- [#36](https://github.com/aep-foundation/aep-node/pull/36) [`46fe593`](https://github.com/aep-foundation/aep-node/commit/46fe593c54bd1cf1efe6961e3994311f969ac274) Thanks [@nkavian](https://github.com/nkavian)! - Add the shared AEP Platform conformance adapter, preserve signing continuation context, and reuse Service-scoped identities across provisioning requests.

## 0.2.4

### Patch Changes

- [#29](https://github.com/aep-foundation/aep-node/pull/29) [`5f1e0f0`](https://github.com/aep-foundation/aep-node/commit/5f1e0f0614d85de2388e3ec96b1e675b7dbfc33c) Thanks [@nkavian](https://github.com/nkavian)! - Align Inspect validation, generated schemas, conformance artifacts, endpoint defaults, and OpenAPI media-type handling with the published AEP drafts.

- Updated dependencies [[`5f1e0f0`](https://github.com/aep-foundation/aep-node/commit/5f1e0f0614d85de2388e3ec96b1e675b7dbfc33c)]:
  - @aep-foundation/core@0.5.1

## 0.2.3

### Patch Changes

- Updated dependencies [[`77daf0a`](https://github.com/aep-foundation/aep-node/commit/77daf0a6830aafeabcd14afd6efaccfdc88bad48)]:
  - @aep-foundation/core@0.5.0

## 0.2.2

### Patch Changes

- Updated dependencies [[`6e252bb`](https://github.com/aep-foundation/aep-node/commit/6e252bb0a0f4c5700b989b43a0f3400bd76099e2)]:
  - @aep-foundation/core@0.4.0

## 0.2.1

### Patch Changes

- Updated dependencies [[`17ecb34`](https://github.com/aep-foundation/aep-node/commit/17ecb340fdd539f0ea6cf1494858f0beb3a0c7a2)]:
  - @aep-foundation/core@0.3.0

## 0.2.0

### Minor Changes

- [#10](https://github.com/aep-foundation/aep-node/pull/10) [`6be44bd`](https://github.com/aep-foundation/aep-node/commit/6be44bdf75e685728d613b6fecfc5b11906617f7) Thanks [@nkavian](https://github.com/nkavian)! - Add cached public-document discovery, OpenAPI authentication policy interpretation, protected-resource fetch workflows, and authenticate assertion support.

- [#8](https://github.com/aep-foundation/aep-node/pull/8) [`18df20b`](https://github.com/aep-foundation/aep-node/commit/18df20b15fbb9c4a141375717e9651a0cdc222ab) Thanks [@nkavian](https://github.com/nkavian)! - Implement unified protected-resource authentication: the `authenticate` assertion operation and exact resource binding, Inspect authentication methods, SDK-owned credential validation and AEP challenges, bounded Agent probe/fetch orchestration, redirect and replay safety, credential cleanup and grant single-flight, and framework protected-resource adapters. Add generic pending Sign resolution across Grant and protected-resource authentication with opaque Platform context, stage-scoped idempotency, cancellation, and typed failures. Inspect caching honors HTTP freshness, supports conditional revalidation, and exposes persistent-cache integration. Also include bounded Inspect transport, Platform authentication headers and identity recovery, generalized Platform idempotency, lifecycle corrections, typed Revoke selectors, and expiration-aware credential selection.

  Allow Agent integrations to provide opaque initial Platform context for delegated signing, including automatically selected Grant types and requested scopes.

  Generalize public-document caching across Inspect, Platform Discovery, and OpenAPI with serializable caller storage and shared revalidation. Add finalized OpenAPI 3.1 advertisement validation, anonymous bounded retrieval, deterministic operation/security interpretation, and policy-aware protected-resource fetch. Grant now requires an existing identity and authoritative active Status before pending signing or credential issuance.

  Add the finalized dedicated protected-resource `AEP-Authorization` carrier
  across Core, Agent, Service, adapters, examples, and synchronized conformance
  artifacts while preserving standard-carrier and API-key behavior.

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
