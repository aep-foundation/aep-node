# Example - Agent did:web inspect

An Agent-side script that bootstraps with the example platform, then inspects any running AEP Service URL.

## Run

Start the platform and a Service first, then run:

```bash
pnpm build
PLATFORM_URL=http://127.0.0.1:4100 SERVICE_URL=http://127.0.0.1:3000 pnpm start
```

The Platform API authorization defaults to `Bearer demo-agent`. Override it with
`PLATFORM_AUTHORIZATION` when the Platform example is configured differently.
