# Complete Inspect Document Example

This example shows a Service that supports the baseline HTTP binding, `did:web`,
and the three initial session-credential grant types.

```http
GET /.well-known/aep HTTP/1.1
Host: api.example.com
Accept: application/aep+json
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
Cache-Control: max-age=300
ETag: "aep-inspect-20260627"
```

```json
{
  "aep_version": "1.0",
  "authentication": {
    "methods": ["aep-jwt", "oauth-bearer", "api-key", "basic"]
  },
  "bindings": {
    "supported": ["http"]
  },
  "claims": {
    "optional": ["owner.name"],
    "preferred": ["owner.organization"],
    "required": ["contact.email"]
  },
  "commands": {
    "grant_types": ["oauth-bearer", "api-key", "basic"],
    "grant_types_config": {
      "api-key": {
        "default_lifetime_seconds": "2592000",
        "header_names": ["aep-service-key"],
        "scopes_supported": ["read", "write"],
        "supports_per_credential_revoke": "true"
      },
      "basic": {
        "default_lifetime_seconds": "86400",
        "realm": "api.example.com",
        "scopes_supported": ["read"],
        "supports_per_credential_revoke": "true"
      },
      "oauth-bearer": {
        "access_token_formats": ["opaque"],
        "default_lifetime_seconds": "900",
        "introspection_endpoint": "https://api.example.com/oauth/introspect",
        "revocation_endpoint": "https://api.example.com/oauth/revoke",
        "scopes_supported": ["read", "write"],
        "supports_per_credential_revoke": "true"
      }
    },
    "supported": ["enroll", "grant", "inspect", "revoke", "status"]
  },
  "core": {
    "signing_algorithms": ["EdDSA", "ES256"]
  },
  "extensions": {
    "supported": []
  },
  "http": {
    "endpoint_base": "/aep/",
    "openapi": {
      "path_matching": { "trailing_slash": "strict" },
      "url": "/openapi.json"
    }
  },
  "identity": {
    "methods": ["did:web"]
  },
  "service": {
    "did": "did:web:api.example.com"
  }
}
```
