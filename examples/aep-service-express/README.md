# Example - AEP Service on Express

An Express Service that mounts AEP routes and protects application routes with AEP client assertion JWTs. It advertises no grant types, so Agent examples use the JWT fallback mode.

## Run

Start `../aep-platform-ephemeral` first, then:

```bash
pnpm build
SERVICE_DID=did:web:127.0.0.1%3A4100:services:example-service PORT=3000 pnpm start
```

The process logs AEP route and protected API interactions after each request.
It does not print JWTs or other bearer material.

Routes:

| Route                  | Purpose                                     |
| ---------------------- | ------------------------------------------- |
| `GET /.well-known/aep` | AEP Inspect document                        |
| `POST /aep/enroll`     | AEP enrollment                              |
| `GET /aep/status`      | AEP enrollment status                       |
| `GET /api/resource`    | Protected resource using AEP JWT auth       |
| `POST /api/profile`    | Protected profile update using AEP JWT auth |
