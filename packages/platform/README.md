# @aep-foundation/platform

Platform-side helpers for managed Agent identity support.

For production storage, authorization, replay, and key-custody guidance, see
the repository [Integration Guide](../../INTEGRATION.md).

Current helpers cover the AEP Platform Hosted Identity Profile:

- create a Platform engine with pluggable persistence, key custody, replay
  storage, authorization, lifecycle policy, and Service DID resolution
- build Platform discovery documents
- build Platform provisioning request and response bodies
- build Service-scoped Agent DIDs
- create managed Agent identity records
- store managed identities in an in-memory registry for tests and prototypes
- build platform-mediated Enroll request bodies
- build baseline AEP client assertion claims for delegated signing flows
- build managed Agent DID documents
- publish DID documents through caller-provided publishers
- sign delegated client assertions with `jose`-backed JWT keys
- verify hosted client assertions without requiring Services to resolve
  Platform-managed Agent DID documents

## Example

```ts
import { createAepPlatform } from "@aep-foundation/platform";

const platform = createAepPlatform({
  didHost: "platform.example.com",
  didUrlTemplate: "https://platform.example.com/agents/{agent_did_id}/did.json",
  discovery: {
    endpointBase: "/v1/aep",
    endpoints: {
      hostedVerification: "/v1/aep/verifications",
      lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
      list: "/v1/aep/agent-identities",
      provision: "/v1/aep/agent-identities",
      sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
    },
    hostedVerification: true,
    platformDid: "did:web:platform.example.com",
    platformName: "Example Platform"
  },
  idGenerator: () => crypto.randomUUID().replaceAll("-", ""),
  idempotencyStore,
  identityStore,
  keyStore,
  replayStore,
  serviceDidResolver,
  signingAlgorithms: ["ES256"]
});

const discovery = platform.discovery();
const provision = await platform.provision(
  {
    idempotency_key: "01J0AEPPLATFORM000000000001",
    service_did: "did:web:api.service.example"
  },
  {
    authorization: "Bearer platform-api-token"
  }
);

const assertion = await platform.sign(
  provision.body.agent_identity_id,
  {
    jti: crypto.randomUUID(),
    lifetime_seconds: "300",
    op: "enroll",
    service_did: provision.body.service_did
  },
  {
    authorization: "Bearer platform-api-token"
  }
);

const verification = await platform.verify({
  client_assertion: assertion.body.client_assertion,
  op: "enroll",
  service_did: provision.body.service_did
});

console.log(discovery.body, provision.body, assertion.body, verification.body);
```

The package does not implement databases, caches, HTTP routing, or key custody.
Callers provide those through `PlatformIdentityStore`,
`PlatformProvisionIdempotencyStore`, `PlatformReplayStore`, `PlatformKeyStore`,
`PlatformServiceDidResolver`, `PlatformAuthorizer`, and
`PlatformLifecyclePolicy`. The example Platform in this repository uses
in-memory implementations for those interfaces.

Low-level helpers remain available when an implementation needs to assemble
individual protocol objects:

```ts
import {
  createManagedAgentDidDocument,
  createManagedAgentIdentity,
  createServiceScopedAgentDid
} from "@aep-foundation/platform";

const agentDid = createServiceScopedAgentDid({
  agentDidId: "4Yf7p2xQd9",
  host: "platform.example.com",
  pathPrefix: "agents"
});

const identity = createManagedAgentIdentity({
  agentDid
});

const didDocument = createManagedAgentDidDocument({
  identity,
  verificationMethods: [
    {
      id: identity.agentDid,
      publicKeyJwk: {
        crv: "P-256",
        kty: "EC",
        x: "...",
        y: "..."
      },
      relationships: ["authentication", "assertionMethod", "capabilityInvocation"],
      type: "JsonWebKey2020"
    }
  ]
});
```
