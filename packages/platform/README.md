# @aep-foundation/platform

Platform-side helpers for managed Agent identity support.

## Install

```sh
pnpm add @aep-foundation/platform
```

Use this package when operating a hosted identity Platform on behalf of
Agents. Agent applications that only consume a Platform should use
`createPlatformIdentityProvider()` from `@aep-foundation/agent` instead.

For production storage, authorization, replay, and key-custody guidance, see
the repository [Integration Guide](../../INTEGRATION.md).

## What It Provides

The package covers the AEP Platform Hosted Identity Profile:

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

## Create a Platform

```ts
import { createAepPlatform } from "@aep-foundation/platform";

const platform = createAepPlatform({
  authorizer: {
    authorize(request, context) {
      return applicationPolicy.allows(request, context);
    }
  },
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
    service_did: "did:web:api.service.example"
  },
  {
    authorization: "Bearer platform-api-token",
    idempotencyKey: "01J0AEPPLATFORM000000000001"
  }
);

if ("code" in provision.body) {
  throw new Error(provision.body.code);
}

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

if ("code" in assertion.body || assertion.body.status !== "completed") {
  throw new Error("Delegated Sign did not complete.");
}

const verification = await platform.verify(
  {
    client_assertion: assertion.body.client_assertion,
    op: "enroll",
    service_did: provision.body.service_did
  },
  {
    authorization: "Bearer platform-api-token"
  }
);

console.log(discovery.body, provision.body, assertion.body, verification.body);
```

Sign callers handle the `status` discriminant and preserve optional
`platform_context` when continuing a pending Platform authorization flow.

The package does not implement databases, caches, HTTP routing, or key custody.
Callers provide those through `PlatformIdentityStore`,
`PlatformIdempotencyStore`, `PlatformReplayStore`, `PlatformKeyStore`,
`PlatformServiceDidResolver`, `PlatformAuthorizer`, and
`PlatformLifecyclePolicy`. The example Platform in this repository uses
in-memory implementations for those interfaces.

`PlatformAuthorizer.authorize()` receives a typed operation request for every
private Platform operation. It must return `true` to permit the request;
`false` fails with the non-disclosing `not_recognized` response. Managed Agent
DID documents remain public so Services can resolve verification material.

`PlatformIdentityStore.findByServiceDid()` scopes lookup through the supplied
request context. It must return the authenticated caller's existing identity
for that Service DID so repeated provisioning with a new idempotency key does
not create another identity. Its `list()` implementation applies deterministic
creation-time and identity-ID ordering before offset and limit, including the
requested `descending` direction.

Provision, Sign, lifecycle, list, and hosted-verification endpoints are part of
the application integration. Publish the Platform discovery document at
`/.well-known/aep-platform` and publish each managed Agent DID document at the
URL derived from that identity's `did:web` value.

Provision, Sign, and hosted Verification require both an `idempotencyKey` and
stable authorization `subject` in `PlatformRequestContext`. Idempotency records
are scoped by subject and key and preserve the operation, canonical request
fingerprint, complete HTTP response, and expiry.

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

## Conformance

Run the shared Platform Hosted Identity Profile vectors against the public
package API:

```sh
pnpm conformance:platform
```
