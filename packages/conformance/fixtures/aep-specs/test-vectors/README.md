# AEP Test Vectors

This directory contains deterministic test vectors for the currently published
AEP Internet-Draft set.

The initial vector set should cover:

| Category                | Purpose                                                                                                                                                             | Draft Coverage                |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| Claim values            | Validate person and contact values, malformed values, negotiation behavior, and forward-compatible Claim Names and object shapes.                                   | Claims                        |
| Inspect document        | Validate required fields, command advertisement, grant type advertisement, `did:web`, HTTP binding configuration, transport trust, and extension discovery shape.   | Core                          |
| Client assertion JWT    | Validate JOSE header fields, JWT claim fields, `aud`, `op`, `iat`, `exp`, and `jti` requirements.                                                                   | Core                          |
| Error response          | Validate AEP Problem Details shape and stable error codes.                                                                                                          | Core                          |
| Idempotency             | Validate safe retry shape, replay retention, header placement, staged Sign keys, and conflict behavior.                                                             | Core and Platform             |
| Enroll request/response | Validate minimal enrollment request and response shape.                                                                                                             | Core                          |
| Status response         | Validate enrolled identity status response shape.                                                                                                                   | Core                          |
| Grant/Revoke request    | Validate shared Grant and Revoke request fields, including revoke-all behavior.                                                                                     | Core plus credential profiles |
| OAuth Bearer credential | Validate OAuth Bearer Grant response, presentation syntax, expiry, scopes, and Revoke shape.                                                                        | OAuth Bearer                  |
| API-key credential      | Validate API-key Grant response, API-key value syntax, header selection, expiry, scopes, and Revoke shape.                                                          | API-key                       |
| Basic credential        | Validate Basic Grant response, generated username/password constraints, Basic presentation syntax, expiry, scopes, and Revoke shape.                                | Basic                         |
| Platform specification  | Validate Platform discovery, Service-scoped Agent DID provisioning, distinct opaque DIDs per Service, delegated signing, lifecycle, and hosted verification shapes. | Platform Hosted Identity      |
| Protected resource      | Validate explicit authentication advertisement, challenge discovery, operation/resource binding, credential presentation, failures, and redirect safety.            | Core plus credential profiles |
| Public document caching | Validate Inspect and Platform Discovery validators, freshness, directives, and final-URL cache keys.                                                                | Core and Platform             |
| OpenAPI discovery       | Validate URL resolution, anonymous retrieval, security inheritance, operation matching, slash modes, and contradiction fallback.                                    | Core                          |

## File Layout

Vectors use one directory per category:

```text
test-vectors/
  caching/
  claims/
  client-assertion/
  credentials/
    api-key/
    basic/
    oauth-bearer/
  enroll/
  errors/
  grant-revoke/
  idempotency/
  inspect/
  openapi/
  platform/
  protected-resource/
  status/
```

Each vector file is JSON. File names use lowercase hyphenated identifiers:

```text
<category>/<vector-id>.json
```

## Vector Format

Each vector has this top-level shape:

```json
{
  "id": "inspect-minimal-http",
  "title": "Minimal HTTP Inspect document",
  "description": "A Service advertising the baseline HTTP binding and current credential profiles.",
  "drafts": ["draft-kavian-agent-enrollment-protocol-02"],
  "category": "inspect",
  "applies_to": ["agent", "service"],
  "profile": "core-http",
  "input": {},
  "expected": {}
}
```

Required fields:

| Field         | Requirement                                                                               |
| ------------- | ----------------------------------------------------------------------------------------- |
| `id`          | Lowercase hyphenated vector identifier.                                                   |
| `title`       | Short human-readable name.                                                                |
| `description` | One- or two-sentence explanation of the behavior under test.                              |
| `drafts`      | Draft identifiers covered by the vector.                                                  |
| `category`    | Vector category.                                                                          |
| `applies_to`  | Array containing `agent`, `service`, or both.                                             |
| `profile`     | `core-http`, `claims`, `platform-hosted-identity`, `oauth-bearer`, `api-key`, or `basic`. |
| `input`       | Test input object.                                                                        |
| `expected`    | Expected output or validation result object.                                              |

## Validation Rules

A vector validator should check at least:

- JSON parseability.
- File path matches `category` and `id`.
- `id` uses lowercase hyphenated syntax.
- `drafts` contains only published AEP draft identifiers.
- `category` is one of the known vector categories.
- `applies_to` contains only known roles.
- `profile` is one of the known profiles.
- `input` and `expected` are JSON objects.
- Claims vectors include positive and negative value-shape cases and
  negotiation compatibility cases.

The validator should not require live network access. Network-dependent checks
belong in the future conformance harness, not in static vector validation.

Run static vector validation with:

```sh
make -C ietf check-vectors
```
