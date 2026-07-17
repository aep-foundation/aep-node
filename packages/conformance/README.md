# @aep-foundation/conformance

Finalized schemas, registries, examples, and vectors are synchronized here.
`loadRegistryArtifact()` and `loadExampleArtifact()` expose the added groups.

SDK-facing conformance helpers for checking AEP behavior against schemas,
examples, and test vectors.

Initial responsibilities:

- load AEP schemas and test vectors
- validate SDK-produced Inspect documents
- validate SDK-produced Enroll request/response and Status response objects
- validate SDK-produced Grant/Revoke request/response and built-in credential
  response objects
- validate AEP Problem Details error responses and idempotency conflict fixtures
- load Platform Hosted Identity schemas and test vectors through stable helpers

## Initial API

```ts
import {
  assertEnrollResponseConformance,
  assertBuiltInGrantResponseConformance,
  assertInspectConformance,
  assertProblemDetailsConformance,
  loadActiveEnrollResponseTestVector,
  loadEnrollIdempotencyConflictTestVector,
  loadOAuthBearerGrantResponseTestVector,
  loadMinimalInspectTestVector,
  loadNotRecognizedProblemTestVector,
  loadPlatformDiscoveryTestVector,
  loadPlatformProvisionRequestTestVector,
  loadPlatformVerificationResponseRecognizedTestVector
} from "@aep-foundation/conformance";

const vector = await loadMinimalInspectTestVector();
const inspect = assertInspectConformance(vector.expected);

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

The initial conformance surface loads synced spec artifacts from
`fixtures/aep-specs`, validates Inspect, Enroll, Status, Grant, Revoke, and
built-in credential response objects, Problem Details errors, and idempotency
conflict fixtures through `@aep-foundation/core`, exposes Platform Hosted
Identity test-vector loaders, and exposes stable fixture path helpers for
package and SDK tests.

## Spec Artifacts

Conformance fixtures are synced from the local `aep-specs` checkout into
`fixtures/aep-specs`.

```sh
pnpm sync:spec-artifacts
```

The script expects `../aep-specs/ietf` relative to the repository root by
default. Set `AEP_SPECS_DIR` to point at another `aep-specs` checkout or at its
`ietf` directory.
