# Example - AEP Service with OAuth bearer credentials

An Express Service that advertises the `oauth-bearer` grant type. Agents enroll with DID-web JWT auth, request an OAuth bearer credential, and use that credential on `GET /api/resource` and `POST /api/profile`.

## Run

Start `../aep-platform-ephemeral` first, then:

```bash
pnpm build
SERVICE_DID=did:web:127.0.0.1%3A3000:services:example-service PORT=3000 pnpm start
```

The process logs AEP route and protected API interactions after each request.
It logs credential issuance by credential id, but does not print bearer tokens.
