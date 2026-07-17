# OpenAPI Authentication Mapping

Inspect advertises this document with `http.openapi.url` equal to `/openapi.json` and strict trailing-slash matching.

```json
{
  "openapi": "3.1.0",
  "components": {
    "securitySchemes": {
      "agentAssertion": {
        "type": "http",
        "scheme": "AEP",
        "x-aep-authentication-method": "aep-jwt"
      },
      "serviceToken": {
        "type": "http",
        "scheme": "bearer",
        "x-aep-authentication-method": "oauth-bearer"
      }
    }
  },
  "security": [{ "serviceToken": [] }],
  "paths": {
    "/v1/orders/{orderId}": {
      "get": { "security": [{ "agentAssertion": [] }, { "serviceToken": [] }] }
    },
    "/health": {
      "get": { "security": [] }
    },
    "/optional": {
      "get": { "security": [{}, { "agentAssertion": [] }] }
    }
  }
}
```

The order lookup accepts either AEP JWT or OAuth Bearer. Health is public. Optional permits anonymous access or AEP JWT. A requirement containing both scheme names would require both; an Agent unable to satisfy both must choose another complete alternative or fall back to live challenge discovery.
