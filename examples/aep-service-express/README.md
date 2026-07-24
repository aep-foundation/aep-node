# Example - AEP Service on Express

An Express Service that mounts AEP routes and protects application routes with AEP client assertion JWTs. It advertises no grant types, so Agent examples use the JWT fallback mode.

The Service advertises `contact.email` and `person.username` as preferred
Claims. Address, mobile, birthdate, first name, and last name are optional. The
paired `../aep-agent-did-web-enroll-status` example supplies the preferred
values and deliberately omits the optional values.

Enrollment Claims are stored in memory; `GET /api/resource` returns only their
names for the authenticated Agent rather than logging or echoing personal Claim
Values.

This example has no required Claims so it remains usable with generic AEP
clients. To exercise required-Claim enforcement, configure a name under
`claims.required`. An Agent SDK client that cannot supply it fails locally with
`AepClaimRequirementsError`; a direct client that sends an incomplete Enroll
request receives `422 requirements_unmet` with `requirements_pending`.

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
