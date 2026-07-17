# Protected-Resource Authorization Carriers

Protected resources accept AEP JWT, OAuth Bearer, and Basic credentials through either carrier:

```http
Authorization: AEP eyJhbGciOiJFZERTQSJ9...
AEP-Authorization: AEP eyJhbGciOiJFZERTQSJ9...
Authorization: Bearer ya29.example
AEP-Authorization: Bearer ya29.example
Authorization: Basic YWVwX2FnZW50OnNlY3JldA==
AEP-Authorization: Basic YWVwX2FnZW50OnNlY3JldA==
```

Each line is a separate valid request example; an Agent sends only one AEP carrier. API keys continue to use the exact header returned by Grant.

## AEP Then MPP

The anonymous request receives only the AEP challenge:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: AEP service_did="did:web:x",inspect="https://x/a"
```

After AEP authentication succeeds, the application can advertise payment. A composed retry keeps payment in standard `Authorization`:

```http
AEP-Authorization: AEP eyJhbGciOiJFZERTQSJ9...
Authorization: Payment mpp-credential
```

## AEP Then x402

An x402-aware retry can compose the dedicated AEP credential with its payment signature:

```http
AEP-Authorization: Bearer ya29.example
PAYMENT-SIGNATURE: x402-signature
```

The AEP layer authenticates the dedicated field and leaves the unrelated payment credential untouched for the payment layer.
