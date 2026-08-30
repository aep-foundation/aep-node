# @aep-foundation/conformance

SDK-facing conformance helpers for checking AEP behavior against schemas,
examples, and test vectors.

## Install

```sh
pnpm add -D @aep-foundation/conformance
```

Use this package in implementation and integration test suites. It is not
required to run the Agent or Service SDK.

## What It Provides

- load AEP schemas and test vectors
- validate AEP Claim Value catalog payloads
- load positive, negative, and forward-compatibility Claims vectors
- validate SDK-produced Inspect documents
- validate SDK-produced Enroll request/response and Status response objects
- validate SDK-produced Grant/Revoke request/response and built-in credential
  response objects
- validate AEP Problem Details error responses and idempotency conflict fixtures
- load Platform Hosted Identity schemas and test vectors through stable helpers

## Example

```ts
import {
  assertBuiltInGrantResponseConformance,
  assertClaimValuesConformance,
  assertEnrollResponseConformance,
  assertInspectConformance,
  assertProblemDetailsConformance,
  loadActiveEnrollResponseTestVector,
  loadClaimValuesTestVector,
  loadEnrollIdempotencyConflictTestVector,
  loadMinimalInspectTestVector,
  loadNotRecognizedProblemTestVector,
  loadOAuthBearerGrantResponseTestVector,
  loadPlatformDiscoveryTestVector,
  loadPlatformProvisionRequestTestVector,
  loadPlatformVerificationResponseRecognizedTestVector
} from "@aep-foundation/conformance";

const vector = await loadMinimalInspectTestVector();
const inspect = assertInspectConformance(vector.expected);

const claimsVector = await loadClaimValuesTestVector();
const claims = assertClaimValuesConformance(claimsVector.expected);

const enrollVector = await loadActiveEnrollResponseTestVector();
const enroll = assertEnrollResponseConformance(enrollVector.expected.body);

const grantVector = await loadOAuthBearerGrantResponseTestVector();
const grant = assertBuiltInGrantResponseConformance("oauth-bearer", grantVector.expected);

const errorVector = await loadNotRecognizedProblemTestVector();
const problem = assertProblemDetailsConformance(errorVector.expected.body);

const conflictVector = await loadEnrollIdempotencyConflictTestVector();
const conflict = assertProblemDetailsConformance(conflictVector.expected.body);

const platformDiscoveryVector = await loadPlatformDiscoveryTestVector();
const platformProvisionVector = await loadPlatformProvisionRequestTestVector();
const hostedVerificationVector = await loadPlatformVerificationResponseRecognizedTestVector();
```

The conformance surface loads synchronized specification artifacts from
`fixtures/aep-specs`, validates Claim Values, Inspect, Enroll, Status, Grant,
Revoke, built-in credential response objects, Problem Details errors, and
idempotency conflict fixtures through `@aep-foundation/core`, exposes Platform
Hosted Identity test-vector loaders, and exposes stable fixture path helpers
for package and SDK tests.

`loadRegistryArtifact()` and `loadExampleArtifact()` expose registry and
descriptive example artifacts when a test needs data beyond the stable named
loaders.

## Spec Artifacts

Conformance fixtures are a reproducible snapshot of the canonical `aep-specs`
artifacts. The published manifest records the exact source revision and a
SHA-256 digest of the generated artifact set.

```sh
pnpm sync:spec-artifacts
```

The script expects `../aep-specs/ietf` relative to the repository root by
default. Set `AEP_SPECS_DIR` to point at another `aep-specs` checkout or at its
`ietf` directory. The relevant source directories must have no uncommitted
changes.

Check the committed snapshot without modifying any files:

```sh
pnpm check:spec-artifacts
```

Continuous integration checks the snapshot against the current canonical
`aep-specs` `main` branch. Specification updates therefore require a dedicated
artifact synchronization change in this repository.
