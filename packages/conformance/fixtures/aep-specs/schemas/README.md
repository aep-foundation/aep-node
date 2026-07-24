# AEP JSON Schemas

This directory contains JSON Schemas for stable AEP wire objects used by the
published Internet-Draft set.

The schemas are validation aids. They do not replace the Internet-Draft prose.
If a schema and a draft disagree, the draft is authoritative and the schema
should be corrected.

## Scope

The initial schema set covers the stable core HTTP objects, the three published
session-credential Grant responses, and the hosted identity Platform specification:

| Schema                                              | Validates                                  |
| --------------------------------------------------- | ------------------------------------------ |
| `api-key-grant-response.schema.json`                | API-key Grant response body                |
| `basic-grant-response.schema.json`                  | HTTP Basic Grant response body             |
| `claim-values.schema.json`                          | Person and contact claim-value shapes      |
| `client-assertion-claims.schema.json`               | Client assertion JWT claim set             |
| `enroll-request.schema.json`                        | Enroll request body                        |
| `enroll-response.schema.json`                       | Enroll response body                       |
| `grant-request.schema.json`                         | Grant request body                         |
| `idempotency-metadata.schema.json`                  | Idempotency key and request hash metadata  |
| `inspect-document.schema.json`                      | Inspect document response body             |
| `oauth-bearer-grant-response.schema.json`           | OAuth Bearer Grant response body           |
| `openapi-aep-security-scheme.schema.json`           | OpenAPI AEP security-scheme extension      |
| `platform-agent-identity-list-response.schema.json` | Platform Agent identity list response body |
| `platform-agent-identity.schema.json`               | Platform Agent identity response body      |
| `platform-discovery.schema.json`                    | Platform discovery document                |
| `platform-lifecycle-request.schema.json`            | Platform lifecycle update request body     |
| `platform-lifecycle-response.schema.json`           | Platform lifecycle update response body    |
| `platform-provision-request.schema.json`            | Platform provisioning request body         |
| `platform-sign-request.schema.json`                 | Platform delegated signing request body    |
| `platform-sign-response.schema.json`                | Platform delegated signing response body   |
| `platform-verification-request.schema.json`         | Platform hosted verification request body  |
| `platform-verification-response.schema.json`        | Platform hosted verification response body |
| `problem.schema.json`                               | AEP Problem Details response body          |
| `protected-resource-authorization.schema.json`      | Protected-resource authorization carrier   |
| `revoke-request.schema.json`                        | Revoke request body                        |
| `revoke-response.schema.json`                       | Revoke response body                       |
| `status-response.schema.json`                       | Status response body                       |

## Validation

Run schema validation with:

```sh
make -C ietf check-schemas
```

The default repository check runs schema validation as part of:

```sh
make -C ietf check
```

The schema checker validates the JSON test vectors that map directly to stable
wire objects. Vectors that describe metadata, JOSE processing, or multi-step
behavior remain covered by the vector structure checker.
