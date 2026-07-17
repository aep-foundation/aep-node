# Enroll, Grant, and Revoke Transcript

This transcript shows the minimum successful flow for an Agent that enrolls with
a Service, requests an OAuth Bearer session credential, revokes one credential,
and then revokes all remaining session credentials. JWT values are abbreviated.

## 1. Enroll

```http
POST /aep/enroll HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: 2e1b6f59-5fd4-4f13-9c2b-0ed4f59e2a11
```

```json
{
  "agent_did": "did:web:agent.example.com:agents:123",
  "claims": {
    "contact.email": "ops@example.com"
  },
  "idempotency_key": "2e1b6f59-5fd4-4f13-9c2b-0ed4f59e2a11"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{
  "status": "active"
}
```

## 2. Grant

```http
POST /aep/grant HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: 3dd9dd29-6fc0-4e68-a886-6d688c5fd3fc
```

```json
{
  "grant_type": "oauth-bearer",
  "requested_scopes": ["read"],
  "token_format": "opaque"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{
  "access_token": "ya29.example",
  "credential_id": "tok_01HZY8W7Q2F8J7D3P9G9Z1N6TT",
  "expires_at": "2026-12-01T00:00:00Z",
  "scopes": ["read"],
  "token_format": "opaque",
  "token_type": "Bearer"
}
```

## 3. Use the Session Credential

```http
GET /v1/orders HTTP/1.1
Host: api.example.com
Authorization: Bearer ya29.example
```

## 4. Revoke One Credential

```http
POST /aep/revoke HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: 2a086218-9d3f-4492-8300-417902e17537
```

```json
{
  "credential_id": "tok_01HZY8W7Q2F8J7D3P9G9Z1N6TT",
  "grant_type": "oauth-bearer"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{}
```

## 5. Revoke All Session Credentials

```http
POST /aep/revoke HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: 71984316-a4f4-4a0a-a980-dbff2cb34bc8
```

```json
{
  "all_grant_types": "true"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{}
```
