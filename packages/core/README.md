# @aep-foundation/core

Protected-resource helpers parse and render standard `Authorization` and
dedicated `AEP-Authorization` carriers while preserving the `AEP`, `Bearer`,
and `Basic` schemes. API-key credentials keep their service-selected field.

Core Agent Enrollment Protocol implementation shared by the Agent, Service,
Platform, adapter, and conformance packages.

Initial responsibilities:

- protocol constants and wire types
- JSON Schema-backed validation helpers
- Inspect document parsing and construction primitives
- HTTP binding helpers
- Problem Details helpers
- client assertion signing and verification primitives
- AEP Claim Value catalog types, schema metadata, and validation helpers
- identity method and grant type registration primitives

## Initial API

The first implemented surface covers the Inspect slice:

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
