# Pending Enroll and Status Polling

This example shows an Enroll response that requires asynchronous verification,
followed by Status polling until the Agent identity becomes active.

## 1. Enroll

```http
POST /aep/enroll HTTP/1.1
Host: api.example.com
Content-Type: application/aep+json
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
Idempotency-Key: 6b7cb1d8-6180-48f3-9d3b-bd9efcd80601
```

```json
{
  "agent_did": "did:web:agent.example.com:agents:123",
  "claims": {
    "contact.email": "ops@example.com"
  },
  "idempotency_key": "6b7cb1d8-6180-48f3-9d3b-bd9efcd80601"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{
  "owner_action_required": "true",
  "status": "pending",
  "verification_pending": ["contact.email"]
}
```

## 2. Poll Status While Pending

```http
GET /aep/status HTTP/1.1
Host: api.example.com
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{
  "requirements_pending": ["contact.email"],
  "since": "2026-06-28T12:00:00Z",
  "status": "pending"
}
```

## 3. Poll Status After Verification Completes

```http
GET /aep/status HTTP/1.1
Host: api.example.com
Accept: application/aep+json
Authorization: AEP eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

```http
HTTP/1.1 200 OK
Content-Type: application/aep+json
```

```json
{
  "since": "2026-06-28T12:05:00Z",
  "status": "active"
}
```
