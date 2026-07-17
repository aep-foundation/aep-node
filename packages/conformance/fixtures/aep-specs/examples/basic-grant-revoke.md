# Basic Grant and Revoke

This example shows Basic session credential issuance, presentation on a later
HTTP request, per-credential Revoke, and grant-type Revoke.

## 1. Grant Basic Credential

```http
POST /aep/grant HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: 46ac413b-3a29-4c8e-a95d-c3ffad46a474
```

```json
{
  "grant_type": "basic",
  "label": "legacy-basic-prod",
  "requested_scopes": ["read"]
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{
  "credential_id": "bas_01HZY8W7Q2F8J7D3P9G9Z1N6TT",
  "expires_at": "2026-12-01T00:00:00Z",
  "password": "s3cr3tExample",
  "realm": "api.example.com",
  "scopes": ["read"],
  "username": "aep_agent_abc123"
}
```

## 2. Present Basic Credential

```http
GET /v1/orders HTTP/1.1
Host: api.example.com
Authorization: Basic YWVwX2FnZW50X2FiYzEyMzpzM2NyM3RFeGFtcGxl
```

## 3. Revoke One Basic Credential

```http
POST /aep/revoke HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: 98ebaaac-a6f0-4a94-98f0-61d74679b00e
```

```json
{
  "credential_id": "bas_01HZY8W7Q2F8J7D3P9G9Z1N6TT",
  "grant_type": "basic"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{}
```

## 4. Revoke All Basic Credentials

```http
POST /aep/revoke HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: ba49f86f-f6b1-40aa-a088-1349fe6b7903
```

```json
{
  "grant_type": "basic"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{}
```
