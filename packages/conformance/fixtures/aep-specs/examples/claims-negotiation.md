# Claim Negotiation Example

This example shows a Service requesting Claims-draft values and an Agent
submitting only the values needed for enrollment.

The Service advertises required, preferred, and optional Claim Names:

```json
{
  "claims": {
    "optional": ["person.username"],
    "preferred": ["contact.mobile", "contact.address.primary", "person.birthdate"],
    "required": ["contact.email", "person.first_name", "person.last_name"]
  }
}
```

The Agent omits unsupported preferred and optional values. It sends the three
required values and one supported preferred value:

```http
POST /aep/enroll HTTP/1.1
Host: api.example.com
Authorization: AEP eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/aep+json

{
  "agent_did": "did:web:agent.example.com:agents:123",
  "claims": {
    "contact.address.primary": {
      "city": "San Francisco",
      "country": "US",
      "delivery_instructions": "Reception desk",
      "first_name": "Grace",
      "last_name": "Hopper",
      "line1": "123 Market Street"
    },
    "contact.email": "owner@example.com",
    "person.first_name": "Ada",
    "person.last_name": "Lovelace"
  },
  "idempotency_key": "9f8a4d2e-1c3b-4f5e-8b7a-000000000001"
}
```

The Service ignores `delivery_instructions` because it does not understand
that additional address member. The omitted preferred and optional Claim
Values do not make the request incomplete.

If the Inspect document instead placed an unknown Claim Name in
`claims.required`, an Agent without local-policy or extension support for that
name could not satisfy the enrollment requirement.
