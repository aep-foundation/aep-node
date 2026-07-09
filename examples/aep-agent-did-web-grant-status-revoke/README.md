# Example - Agent did:web grant, status, and revoke

An Agent-side script that bootstraps with the example platform, enrolls with a running AEP Service, requests the first advertised built-in grant type, calls protected API routes, checks status, and revokes the credential.

If the Service advertises no built-in grant types, the script falls back to AEP JWT authentication for the protected API calls and reports `grant`/`revoke` as `null`.

## Run

Start the platform and any role-oriented Service first, then run:

```bash
pnpm build
PLATFORM_URL=http://127.0.0.1:4100 SERVICE_URL=http://127.0.0.1:3000 pnpm start
```

The Platform API authorization defaults to `Bearer demo-agent`. Override it with
`PLATFORM_AUTHORIZATION` when the Platform example is configured differently.
