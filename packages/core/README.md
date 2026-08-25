# @aep-foundation/core

Core Agent Enrollment Protocol implementation shared by the Agent, Service,
Platform, adapter, and conformance packages.

Most applications should install [`@aep-foundation/agent`](../agent/README.md)
or [`@aep-foundation/service`](../service/README.md) instead. Install Core
directly when implementing protocol objects, validation, signing, or HTTP
bindings without the higher-level workflows.

## Install

```sh
pnpm add @aep-foundation/core
```

The package is ESM-first, includes a CommonJS entry point, and requires Node.js
22 or newer.

## What It Provides

- protocol constants and wire types
- JSON Schema-backed validation helpers
- Inspect document parsing and construction primitives
- HTTP binding helpers
- Problem Details helpers
- client assertion signing and verification primitives
- AEP Claim Value catalog types, schema metadata, and validation helpers
- identity method and grant type registration primitives

Protected-resource helpers parse and render standard `Authorization` and
dedicated `AEP-Authorization` carriers while preserving the `AEP`, `Bearer`,
and `Basic` schemes. API-key credentials keep their Service-selected field.

## Example

```ts
import {
  commandPathFromInspect,
  parseInspectDocument,
  validateAepClaimValues
} from "@aep-foundation/core";

const inspect = parseInspectDocument(await response.json());
const enrollPath = commandPathFromInspect(inspect, "enroll");
const claims = validateAepClaimValues({
  "contact.email": "agent@example.com"
});

if (!claims.ok) {
  throw new Error("The AEP Claim Values are invalid.");
}
```

`parseInspectDocument()` rejects invalid Service documents rather than
returning a partial result. `commandPathFromInspect()` uses the fixed command
paths advertised through the validated document.

## Public Surface

The package exports:

- `AEP_VERSION`, `AEP_MEDIA_TYPE`, `AEP_AUTH_SCHEME`, and command/grant type
  constants
- `InspectDocument` and related wire types
- `inspectDocumentSchema` and `claimValuesSchema`
- `validateInspectDocument`, `parseInspectDocument`, and `isInspectDocument`
- `AEP_CLAIM_NAMES`, `AEP_CLAIM_NAME_*`, `validateAepClaimValues`,
  `parseAepClaimValues`, and `isAepClaimValues`
- `evaluateAepClaimSupport` and `missingAepRequiredClaimNames`
- `commandPath` and `commandPathFromInspect`
- `createProblemDetails`
- `signClientAssertionJwt` and `verifyClientAssertionJwt` for baseline AEP
  client assertion JWTs using `jose`
- `didWebDocumentUrl` and `resolveDidWebPublicKey` for DID-web document and
  public-key lookup
- `decodeJwtUnverified` for reading untrusted JWT headers and payloads before
  key resolution

JWT helpers accept PEM (`pkcs8`, `spki`, or `x509`), JWK, `CryptoKey`,
`KeyObject`, or raw key material where `jose` supports it.

The registered email Claim validator implements the RFC 5321 `Mailbox`
grammar, including quoted local parts and address literals. Syntax validation
does not establish that a mailbox exists or is controlled by the submitter.

See the [AEP specifications](https://www.aep.foundation/) for the normative
wire contract and the [repository integration guide](../../INTEGRATION.md) for
production boundaries.
