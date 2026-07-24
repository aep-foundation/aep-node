# API-key Grant and Revoke

This example shows API-key session credential issuance, presentation on a later
HTTP request, per-credential Revoke, and grant-type Revoke.

## 1. Grant API-key Credential

```http
POST /aep/grant HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: c95be1c5-44c3-4610-99d8-985cd343a20e
```

```json
{
  "grant_type": "api-key",
  "label": "agent-prod-read",
  "requested_scopes": ["read"]
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{
  "api_key": "aep_live_7Jm5Example",
  "credential_id": "key_01HZY8W7Q2F8J7D3P9G9Z1N6TT",
  "expires_at": "2026-12-01T00:00:00Z",
  "header": "x-api-key",
  "scopes": ["read"]
}
```

## 2. Present API-key Credential

```http
GET /v1/orders HTTP/1.1
Host: api.example.com
x-api-key: aep_live_7Jm5Example
```

## 3. Revoke One API-key Credential

```http
POST /aep/revoke HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: d87a8f13-efce-4ad9-bd20-5efcd015a8bb
```

```json
{
  "credential_id": "key_01HZY8W7Q2F8J7D3P9G9Z1N6TT",
  "grant_type": "api-key"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{}
```

## 4. Revoke All API-key Credentials

```http
POST /aep/revoke HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: c733abec-e668-4e1e-807b-15a1013b76eb
```

```json
{
  "grant_type": "api-key"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{}
```
