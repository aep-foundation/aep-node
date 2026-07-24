# Example - Agent did:web enroll and status

An Agent-side script that bootstraps with the example platform, negotiates AEP
Claims advertised by a running Service, enrolls, checks status, then calls
protected application routes.

The example Agent has locally available values for `contact.email` and
`person.username`. After Inspect, it:

1. verifies that it can supply every required Claim Name;
2. submits available required and preferred Claim Values;
3. omits optional Claims to demonstrate that they do not block enrollment; and
4. prints only the submitted Claim Names, not their personal values.

If the Service advertises an unavailable required Claim Name, the script stops
before Enroll and identifies the unsupported names. The Agent SDK independently
enforces the same preflight rule with `AepClaimRequirementsError`.

## Run

Start the platform and a Service first, then run:

```bash
pnpm build
PLATFORM_URL=http://127.0.0.1:4100 SERVICE_URL=http://127.0.0.1:3000 pnpm start
```

The Platform API authorization defaults to `Bearer demo-agent`. Override it with
`PLATFORM_AUTHORIZATION` when the Platform example is configured differently.

When the Service advertises no grant types, this example signs fresh AEP client assertion JWTs for the protected `/api/*` calls.

The paired `../aep-service-express` example advertises email and username as
preferred, so running these two examples together demonstrates a successful
Inspect → negotiate → Enroll Claims flow.
