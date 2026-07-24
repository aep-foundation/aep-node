# Protected-Resource Authentication

This example shows explicit authentication advertisement, challenge-driven discovery, and a resource-bound AEP assertion. `authenticate` is an assertion operation, not an AEP command endpoint.

## Inspect Advertisement

```json
{
  "aep_version": "1.0",
  "authentication": { "methods": ["aep-jwt", "oauth-bearer", "api-key", "basic"] },
  "bindings": { "supported": ["http"] },
  "commands": {
    "grant_types": ["oauth-bearer", "api-key", "basic"],
    "supported": ["inspect", "enroll", "grant", "revoke", "status"]
  },
  "core": { "signing_algorithms": ["EdDSA", "ES256"] },
  "http": { "endpoint_base": "/aep/" },
  "identity": { "methods": ["did:web"] },
  "service": { "did": "did:web:api.example.com" }
}
```

The method order is the Service preference. JWT-only advertisement uses `["aep-jwt"]`; credential-only advertisement omits `aep-jwt`. Omitting `authentication` advertises no protected-resource authentication method.

## Challenge and AEP JWT

```http
GET /v1/orders/123 HTTP/1.1
Host: api.example.com
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: AEP service_did="did:web:api.example.com", inspect="https://api.example.com/.well-known/aep", reason="authentication_required"
```

The Agent obtains a fresh assertion containing:

```json
{
  "aud": "did:web:api.example.com",
  "exp": 1783958460,
  "iat": 1783958400,
  "iss": "did:web:agent.example.com:agents:123",
  "jti": "01J0AEPRESOURCE000000000001",
  "op": "authenticate",
  "resource": "https://api.example.com/v1/orders/123",
  "sub": "did:web:agent.example.com:agents:123"
}
```

```http
GET /v1/orders/123 HTTP/1.1
Host: api.example.com
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

OAuth Bearer and Basic credentials use their registered `Authorization` schemes. An API key uses the exact `header` returned by Grant, for example `x-api-key`; the header name is not fixed by AEP.

## Redirects

For a same-origin redirect to `/v1/orders/124`, the Agent obtains a new assertion whose `resource` names that target. For a redirect to another origin, it removes all AEP and AEP-issued credentials and restarts with an anonymous request. The new origin must issue its own valid AEP challenge before authentication begins.
