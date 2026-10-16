import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  resolveDidWebPublicKey,
  signClientAssertionJwt,
  verifyClientAssertionJwt
} from "@aep-foundation/core";

import {
  AEP_PLATFORM_VERIFICATION_REASONS,
  InMemoryManagedAgentRegistry,
  createAepPlatform,
  createInMemoryPlatformIdempotencyStore,
  createJwtPlatformDelegatedSigner,
  createManagedAgentDidDocument,
  createManagedAgentIdentity,
  createPlatformAgentIdentity,
  createPlatformAgentIdentityListResponse,
  createPlatformClientAssertionClaims,
  createPlatformDiscoveryDocument,
  createPlatformEnrollRequest,
  createPlatformSignPendingResponse,
  createPlatformSignResponse,
  createPlatformVerificationRequest,
  createPlatformVerificationResponse,
  createServiceScopedAgentDid,
  defaultAssertionLifetimeSeconds,
  maxAssertionLifetimeSeconds,
  publishManagedAgentDidDocument,
  signPlatformClientAssertion,
  updateManagedAgentIdentity
} from "../src/index.js";
import type {
  CreateAepPlatformOptions,
  ManagedAgentStatus,
  PlatformDiscoveryDocumentOptions,
  PlatformIdempotencyRecord,
  PlatformIdempotencyStore,
  PlatformIdentityRecord,
  PlatformIdentityStore,
  PlatformReplayStore
} from "../src/index.js";

const SERVICE_DID = "did:web:api.service.example";
const AGENT_DID = "did:web:platform.example:agents:abc";

function managedIdentity(status: ManagedAgentStatus = "active") {
  return {
    agentDid: AGENT_DID,
    createdAt: "2026-01-01T00:00:00.000Z",
    metadata: {},
    status,
    updatedAt: "2026-01-01T00:00:00.000Z"
  };
}

function discoveryOptions(
  overrides: Partial<PlatformDiscoveryDocumentOptions> = {}
): PlatformDiscoveryDocumentOptions {
  return {
    didUrlTemplate: "https://platform.example/agents/{agent_did_id}/did.json",
    endpointBase: "/v1/aep",
    endpoints: {
      lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
      list: "/v1/aep/agent-identities",
      provision: "/v1/aep/agent-identities",
      sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
    },
    platformName: "Example Platform",
    signingAlgorithms: ["EdDSA"],
    ...overrides
  };
}

describe("PLT-SIGN-010/011 — the effective assertion lifetime is capped at 300 seconds", () => {
  it("exports the specification ceiling", () => {
    expect(maxAssertionLifetimeSeconds).toBe(300);
    expect(defaultAssertionLifetimeSeconds).toBe(300);
  });

  it("refuses a lifetime above 300 seconds even when a longer maximum is configured", () => {
    expect(() =>
      createPlatformClientAssertionClaims({
        command: "enroll",
        identity: managedIdentity(),
        issuedAt: new Date("2026-01-01T00:00:00Z"),
        jti: "jti-1",
        lifetimeSeconds: 86_400,
        maxLifetimeSeconds: 86_400,
        serviceDid: SERVICE_DID
      })
    ).toThrow(/must not exceed 300 seconds/u);

    expect(() =>
      createPlatformSignResponse({
        clientAssertion: "a.b.c",
        identity: managedIdentity(),
        jti: "jti-1",
        lifetimeSeconds: 301,
        maxLifetimeSeconds: 86_400,
        serviceDid: SERVICE_DID
      })
    ).toThrow(/must not exceed 300 seconds/u);
  });

  it("still honours a shorter local maximum", () => {
    expect(() =>
      createPlatformClientAssertionClaims({
        command: "enroll",
        identity: managedIdentity(),
        jti: "jti-1",
        lifetimeSeconds: 120,
        maxLifetimeSeconds: 60,
        serviceDid: SERVICE_DID
      })
    ).toThrow(/must not exceed 60 seconds/u);

    const claims = createPlatformClientAssertionClaims({
      command: "enroll",
      identity: managedIdentity(),
      issuedAt: new Date("2026-01-01T00:00:00Z"),
      jti: "jti-1",
      lifetimeSeconds: 60,
      maxLifetimeSeconds: 60,
      serviceDid: SERVICE_DID
    });

    expect(claims.exp - claims.iat).toBe(60);
  });

  it("refuses to advertise a default lifetime above the ceiling", () => {
    expect(() =>
      createPlatformDiscoveryDocument(
        discoveryOptions({ defaultLifetimeSeconds: 86_400, maxLifetimeSeconds: 86_400 })
      )
    ).toThrow(/must not exceed 300 seconds/u);

    expect(
      createPlatformDiscoveryDocument(discoveryOptions({ defaultLifetimeSeconds: 120 })).signing
        .default_lifetime_seconds
    ).toBe("120");
  });

  it("rejects non-integer and non-positive lifetimes and maximums", () => {
    const base = {
      command: "enroll" as const,
      identity: managedIdentity(),
      jti: "jti-1",
      serviceDid: SERVICE_DID
    };

    expect(() => createPlatformClientAssertionClaims({ ...base, lifetimeSeconds: 0 })).toThrow(
      /positive integer/u
    );
    expect(() => createPlatformClientAssertionClaims({ ...base, lifetimeSeconds: 1.5 })).toThrow(
      /positive integer/u
    );
    expect(() =>
      createPlatformClientAssertionClaims({ ...base, lifetimeSeconds: 60, maxLifetimeSeconds: 0 })
    ).toThrow(/maxLifetimeSeconds must be a positive integer/u);
  });
});

describe("advertised endpoints stay on the Platform origin", () => {
  it("refuses an authority, backslash, control character, query, or fragment", () => {
    const hostile = [
      "//evil.example/sign",
      "/\\evil.example/sign",
      "/sign\r\nX-Injected: 1",
      "/sign#fragment",
      "/sign?next=https://evil.example",
      "/sign with space"
    ];

    for (const sign of hostile) {
      expect(() =>
        createPlatformDiscoveryDocument(
          discoveryOptions({ endpoints: { ...discoveryOptions().endpoints, sign } })
        )
      ).toThrow(TypeError);
    }
  });

  it("refuses an off-origin endpoint base and hosted verification path", () => {
    expect(() =>
      createPlatformDiscoveryDocument(discoveryOptions({ endpointBase: "//evil.example/v1" }))
    ).toThrow(TypeError);

    expect(() =>
      createPlatformDiscoveryDocument(
        discoveryOptions({
          endpoints: { ...discoveryOptions().endpoints, hostedVerification: "//evil.example/v" }
        })
      )
    ).toThrow(TypeError);

    expect(() =>
      createPlatformDiscoveryDocument(discoveryOptions({ endpointBase: "v1/aep" }))
    ).toThrow(/must start with/u);
  });

  it("accepts ordinary templated paths and a trailing slash", () => {
    const document = createPlatformDiscoveryDocument(
      discoveryOptions({
        endpointBase: "/v1/aep/",
        endpoints: {
          hostedVerification: "/v1/aep/verifications",
          lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
          list: "/v1/aep/agent-identities",
          provision: "/v1/aep/agent-identities",
          sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
        },
        hostedVerification: true
      })
    );

    expect(document.http.endpoint_base).toBe("/v1/aep/");
    expect(document.endpoints.hosted_verification).toBe("/v1/aep/verifications");

    for (const endpoint of Object.values(document.endpoints) as string[]) {
      expect(new URL(endpoint, "https://platform.example/base/").origin).toBe(
        "https://platform.example"
      );
    }
  });

  it("validates the remaining discovery inputs", () => {
    expect(() =>
      createPlatformDiscoveryDocument(discoveryOptions({ didUrlTemplate: "http://platform/{x}" }))
    ).toThrow(/HTTPS URL template/u);
    expect(() =>
      createPlatformDiscoveryDocument(discoveryOptions({ platformDid: "platform.example" }))
    ).toThrow(/must be a DID/u);
    expect(() =>
      createPlatformDiscoveryDocument(discoveryOptions({ signingAlgorithms: [] }))
    ).toThrow(/at least one algorithm/u);
    expect(() => createPlatformDiscoveryDocument(discoveryOptions({ didMethods: [] }))).toThrow(
      /at least one DID method/u
    );
    expect(() =>
      createPlatformDiscoveryDocument(discoveryOptions({ platformName: "   " }))
    ).toThrow(/non-empty string/u);
  });
});

describe("PLT-SIGN-022 / PLT-DID-005 — a Service resolves the published key by the bare Agent DID", () => {
  it("publishes the primary verification method under the Agent DID with no fragment", () => {
    const document = createManagedAgentDidDocument({
      identity: managedIdentity(),
      verificationMethods: [{ publicKeyJwk: { kty: "OKP" }, type: "JsonWebKey2020" }]
    });

    expect(document.verificationMethod?.[0]?.id).toBe(AGENT_DID);
    expect(document.authentication).toEqual([AGENT_DID]);
  });

  it("keeps fragment identifiers for additional methods and honours explicit ids", () => {
    const document = createManagedAgentDidDocument({
      identity: managedIdentity(),
      verificationMethods: [
        { publicKeyJwk: { kty: "OKP" }, relationships: ["authentication"], type: "JsonWebKey2020" },
        { publicKeyJwk: { kty: "EC" }, relationships: ["assertionMethod"], type: "JsonWebKey2020" },
        { id: `${AGENT_DID}#custom`, publicKeyJwk: { kty: "EC" }, type: "JsonWebKey2020" }
      ]
    });

    expect(document.verificationMethod?.map((method) => method.id)).toEqual([
      AGENT_DID,
      `${AGENT_DID}#key-2`,
      `${AGENT_DID}#custom`
    ]);
    expect(document.assertionMethod).toEqual([`${AGENT_DID}#key-2`]);
  });

  it("verifies a delegated assertion end to end against the published document", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyJwk = publicKey.export({ format: "jwk" });
    const identity = managedIdentity();

    const didDocument = createManagedAgentDidDocument({
      identity,
      verificationMethods: [{ publicKeyJwk, type: "JsonWebKey2020" }]
    });

    const clientAssertion = await signPlatformClientAssertion({
      command: "enroll",
      identity,
      jti: "jti-e2e",
      serviceDid: SERVICE_DID,
      signer: createJwtPlatformDelegatedSigner({ key: privateKey }),
      signingAlgorithms: ["EdDSA"]
    });

    const header = JSON.parse(
      Buffer.from(clientAssertion.split(".")[0] ?? "", "base64url").toString("utf8")
    ) as { kid: string };

    expect(header.kid).toBe(AGENT_DID);

    const jwk = await resolveDidWebPublicKey({
      did: AGENT_DID,
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify(didDocument), {
            headers: { "content-type": "application/json" },
            status: 200
          })
        ),
      kid: header.kid
    });

    const claims = await verifyClientAssertionJwt(clientAssertion, {
      algorithms: ["EdDSA"],
      audience: SERVICE_DID,
      key: jwk
    });

    expect(claims).toMatchObject({
      aud: SERVICE_DID,
      iss: AGENT_DID,
      op: "enroll",
      sub: AGENT_DID
    });
  });

  it("requires at least one verification method and rejects unusable identities", () => {
    expect(() =>
      createManagedAgentDidDocument({ identity: managedIdentity(), verificationMethods: [] })
    ).toThrow(/at least one method/u);

    expect(() =>
      createManagedAgentDidDocument({
        identity: managedIdentity("suspended"),
        verificationMethods: [{ publicKeyJwk: { kty: "OKP" }, type: "JsonWebKey2020" }]
      })
    ).toThrow(/not active/u);
  });

  it("carries controller, contexts, and services through publication", async () => {
    const publication = await publishManagedAgentDidDocument({
      additionalContexts: ["https://w3id.org/security/suites/jws-2020/v1"],
      controller: "did:web:platform.example",
      identity: managedIdentity(),
      publisher: {
        publish(document) {
          return {
            document,
            publishedAt: "2026-01-01T00:00:00.000Z",
            url: "https://platform.example/agents/abc/did.json"
          };
        }
      },
      service: [{ id: `${AGENT_DID}#svc`, serviceEndpoint: "https://x.example", type: "Example" }],
      verificationMethods: [{ publicKeyJwk: { kty: "OKP" }, type: "JsonWebKey2020" }]
    });

    expect(publication.document["@context"]).toContain(
      "https://w3id.org/security/suites/jws-2020/v1"
    );
    expect(publication.document.controller).toBe("did:web:platform.example");
    expect(publication.document.service?.[0]?.id).toBe(`${AGENT_DID}#svc`);
  });
});

describe("PLT-VER-008 — the verification reason vocabulary is closed", () => {
  it("exports the two permitted reasons", () => {
    expect([...AEP_PLATFORM_VERIFICATION_REASONS]).toEqual(["not_recognized", "verified"]);
  });

  it("refuses a reason outside the vocabulary", () => {
    expect(() =>
      createPlatformVerificationResponse({
        // @ts-expect-error the reason vocabulary is closed at the type level too
        reason: "identity_suspended",
        serviceDid: SERVICE_DID,
        verified: false
      })
    ).toThrow(/'not_recognized' or 'verified'/u);
  });

  it("refuses a response whose verified flag contradicts its reason", () => {
    expect(() =>
      createPlatformVerificationResponse({
        reason: "not_recognized",
        serviceDid: SERVICE_DID,
        verified: true
      })
    ).toThrow(/verified must be true exactly when/u);

    expect(() =>
      createPlatformVerificationResponse({
        reason: "verified",
        serviceDid: SERVICE_DID,
        verified: false
      })
    ).toThrow(/verified must be true exactly when/u);
  });

  it("requires a service DID", () => {
    expect(() =>
      createPlatformVerificationResponse({
        reason: "not_recognized",
        serviceDid: "  ",
        verified: false
      })
    ).toThrow(/non-empty string/u);
  });

  it("requires resource exactly for authenticate verification requests", () => {
    expect(() =>
      createPlatformVerificationRequest({
        clientAssertion: "a.b.c",
        command: "authenticate",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/resource is required only for authenticate/u);

    expect(() =>
      createPlatformVerificationRequest({
        clientAssertion: "a.b.c",
        command: "enroll",
        resource: "https://api.service.example/x",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/resource is required only for authenticate/u);

    expect(() =>
      createPlatformVerificationRequest({
        clientAssertion: "   ",
        command: "enroll",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/non-empty string/u);
  });
});

describe("PLT-ERR-001/002 — an unparseable body is Problem Details, not a thrown error", () => {
  it("answers every command with 400 invalid_request", async () => {
    const platform = createAepPlatform(platformOptions());
    const context = { idempotencyKey: "key-1", subject: "owner-1" };

    const cases: Promise<{ body: unknown; status: number }>[] = [
      platform.provision(null, context),
      platform.provision({}, context),
      platform.provision([], context),
      platform.sign("pai_1", { jti: "j", op: "inspect", service_did: SERVICE_DID }, context),
      platform.sign("pai_1", [], context),
      platform.sign(
        { jti: "j", op: "enroll", service_did: SERVICE_DID, lifetime_seconds: "99999" } as never,
        {},
        context
      ),
      platform.updateIdentity("pai_1", { status: "ACTIVE" }, context),
      platform.updateIdentity("pai_1", null, context),
      platform.verify({ op: "enroll", service_did: SERVICE_DID }, context),
      platform.verify("nope", context)
    ];

    for (const pending of cases) {
      const response = await pending;

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        code: "invalid_request",
        status: 400,
        title: "Bad Request",
        type: "urn:aep:error:invalid_request"
      });
      expect((response.body as { detail?: string }).detail).toBeTypeOf("string");
    }
  });

  it("reports a non-Error rejection without leaking its shape", async () => {
    const platform = createAepPlatform(platformOptions());
    const response = await platform.sign(
      "pai_1",
      { jti: "j", op: "enroll", platform_context: "not-an-object", service_did: SERVICE_DID },
      { idempotencyKey: "key-1", subject: "owner-1" }
    );

    expect(response.status).toBe(400);
  });
});

describe("PLT-IDP — idempotency scoping, fingerprinting, and retention", () => {
  it("refuses an advertised default above the signing maximum at construction", () => {
    expect(() => createAepPlatform(platformOptions({ maxLifetimeSeconds: 60 }))).toThrow(
      /must not exceed 60 seconds/u
    );

    expect(() =>
      createAepPlatform(platformOptions({ defaultLifetimeSeconds: 60, maxLifetimeSeconds: 60 }))
    ).not.toThrow();
  });

  it("refuses a retention window shorter than one hour at construction", () => {
    expect(() => createAepPlatform(platformOptions({ idempotencyRetentionSeconds: 60 }))).toThrow(
      RangeError
    );
    expect(() =>
      createAepPlatform(platformOptions({ idempotencyRetentionSeconds: 3600.5 }))
    ).toThrow(RangeError);
    expect(() =>
      createAepPlatform(platformOptions({ idempotencyRetentionSeconds: 7200 }))
    ).not.toThrow();
  });

  it("fingerprints member order independently of insertion order", async () => {
    const records: PlatformIdempotencyRecord[] = [];
    const store = recordingIdempotencyStore(records);
    const identities = memoryIdentityStore();
    await identities.create(identityRecord(), {});
    const platform = createAepPlatform(
      platformOptions({ idempotencyStore: store, identityStore: identities })
    );

    await platform.sign(
      "pai_1",
      { jti: "same", op: "enroll", service_did: SERVICE_DID },
      { idempotencyKey: "key-a", subject: "owner-1" }
    );
    await platform.sign(
      "pai_1",
      { service_did: SERVICE_DID, op: "enroll", jti: "same" },
      { idempotencyKey: "key-b", subject: "owner-1" }
    );

    expect(records).toHaveLength(2);
    expect(records[0]?.fingerprint).toBe(records[1]?.fingerprint);
  });

  it("canonicalizes nested arrays inside opaque platform context", async () => {
    const records: PlatformIdempotencyRecord[] = [];
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        idempotencyStore: recordingIdempotencyStore(records),
        identityStore: store
      })
    );

    await platform.sign(
      "pai_1",
      {
        jti: "jti-array",
        op: "enroll",
        platform_context: { steps: [1, "two", { three: true }] },
        service_did: SERVICE_DID
      },
      { idempotencyKey: "sign-array", subject: "owner-1" }
    );

    expect(records).toHaveLength(1);
    expect(records[0]?.fingerprint).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("separates principals and reports a conflict on changed material", async () => {
    const platform = createAepPlatform(platformOptions());

    const first = await platform.provision(
      { service_did: SERVICE_DID },
      { idempotencyKey: "shared-key", subject: "owner-1" }
    );
    const otherPrincipal = await platform.provision(
      { service_did: "did:web:other.example" },
      { idempotencyKey: "shared-key", subject: "owner-2" }
    );

    expect(first.status).toBe(200);
    expect(otherPrincipal.status).toBe(200);

    const conflict = await platform.provision(
      { service_did: "did:web:changed.example" },
      { idempotencyKey: "shared-key", subject: "owner-1" }
    );

    expect(conflict.status).toBe(409);
    expect(conflict.body).toMatchObject({ code: "idempotency_conflict" });
  });

  it("re-executes once a stored record has expired", async () => {
    let executions = 0;
    const platform = createAepPlatform(
      platformOptions({
        idempotencyStore: createInMemoryPlatformIdempotencyStore([
          {
            expiresAt: "2020-01-01T00:00:00.000Z",
            fingerprint: "stale",
            idempotencyKey: "key-a",
            operation: "provision",
            principal: "owner-1",
            response: { body: { stale: true }, contentType: "application/aep+json", status: 200 }
          }
        ]),
        serviceDidResolver: {
          resolve() {
            executions += 1;
            return true;
          }
        }
      })
    );

    const response = await platform.provision(
      { service_did: SERVICE_DID },
      { idempotencyKey: "key-a", subject: "owner-1" }
    );

    expect(response.body).not.toMatchObject({ stale: true });
    expect(response.status).toBe(200);
    expect(executions).toBe(1);
  });

  it("requires both an idempotency key and a stable principal", async () => {
    const platform = createAepPlatform(platformOptions());

    await expect(platform.provision({ service_did: SERVICE_DID }, {})).resolves.toMatchObject({
      body: { code: "invalid_request" },
      status: 400
    });
    await expect(
      platform.provision({ service_did: SERVICE_DID }, { idempotencyKey: "", subject: "owner-1" })
    ).resolves.toMatchObject({ status: 400 });
    await expect(
      platform.provision({ service_did: SERVICE_DID }, { idempotencyKey: "k", subject: "" })
    ).resolves.toMatchObject({ status: 400 });
  });
});

describe("PLT-ERR-005 / PLT-VER-009 — denied operations are indistinguishable from absent ones", () => {
  it("requires an authorizer at construction", () => {
    expect(() =>
      createAepPlatform({ ...platformOptions(), authorizer: undefined as never })
    ).toThrow(/authorizer.authorize is required/u);
    expect(() =>
      createAepPlatform({ ...platformOptions(), authorizer: { authorize: "no" } as never })
    ).toThrow(/authorizer.authorize is required/u);
    expect(() => createAepPlatform({ ...platformOptions(), signingAlgorithms: [] })).toThrow(
      /at least one algorithm/u
    );
    expect(() => createAepPlatform({ ...platformOptions(), didHost: "  " })).toThrow(
      /non-empty string/u
    );
  });

  it("returns 404 not_recognized for denied reads, lists, and updates", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({ authorizer: { authorize: () => false }, identityStore: store })
    );

    await expect(platform.getIdentity("pai_1")).resolves.toMatchObject({
      body: { code: "not_recognized" },
      status: 404
    });
    await expect(platform.list()).resolves.toMatchObject({
      body: { code: "not_recognized" },
      status: 404
    });
    await expect(
      platform.updateIdentity(
        "pai_1",
        { status: "revoked" },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "not_recognized" }, status: 404 });
    await expect(
      platform.sign(
        "pai_1",
        { jti: "j", op: "enroll", service_did: SERVICE_DID },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "not_recognized" }, status: 404 });
  });

  it("returns 404 for an identity that does not exist", async () => {
    const platform = createAepPlatform(platformOptions());

    await expect(platform.getIdentity("pai_missing")).resolves.toMatchObject({ status: 404 });
    await expect(platform.getDidDocument("pai_missing")).resolves.toMatchObject({
      body: { code: "not_recognized" },
      status: 404
    });
    await expect(
      platform.updateIdentity(
        "pai_missing",
        { status: "revoked" },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ status: 404 });
  });

  it("returns 404 when the store forgets the identity between authorization and update", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        identityStore: {
          ...store,
          update() {
            return undefined;
          }
        }
      })
    );

    await expect(
      platform.updateIdentity(
        "pai_1",
        { status: "revoked" },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "not_recognized" }, status: 404 });
  });
});

describe("PLT-SIGN-007 / PLT-LIFE-002 — inactive identities cannot sign", () => {
  const codes: [ManagedAgentStatus, string][] = [
    ["revoked", "identity_suspended"],
    ["suspended", "identity_suspended"],
    ["terminated", "identity_terminated"]
  ];

  it.each(codes)("refuses to sign for a %s identity", async (status, code) => {
    const store = memoryIdentityStore();
    await store.create(identityRecord({ status }), {});

    const platform = createAepPlatform(platformOptions({ identityStore: store }));
    const response = await platform.sign(
      "pai_1",
      { jti: "j", op: "enroll", service_did: SERVICE_DID },
      { idempotencyKey: "k", subject: "owner-1" }
    );

    expect(response.status).toBe(403);
    expect(response.body).toMatchObject({ code });
  });

  it("falls back to identity_unavailable when a policy refuses an active identity", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        identityStore: store,
        lifecyclePolicy: {
          canSign: () => false,
          canTransition: () => true,
          canVerify: () => true
        }
      })
    );

    await expect(
      platform.sign(
        "pai_1",
        { jti: "j", op: "enroll", service_did: SERVICE_DID },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "identity_unavailable" }, status: 403 });
  });

  it("refuses a sign request whose service DID does not match the identity", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(platformOptions({ identityStore: store }));

    await expect(
      platform.sign(
        "pai_1",
        { jti: "j", op: "enroll", service_did: "did:web:other.example" },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "not_recognized" }, status: 404 });
  });

  it("refuses a sign request whose service DID cannot be resolved", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({ identityStore: store, serviceDidResolver: { resolve: () => false } })
    );

    await expect(
      platform.sign(
        "pai_1",
        { jti: "j", op: "enroll", service_did: SERVICE_DID },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });
  });

  it("applies an accepted lifecycle transition and returns the updated identity", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({ clock: () => new Date("2026-08-01T00:00:00.000Z"), identityStore: store })
    );

    const response = await platform.updateIdentity(
      "pai_1",
      { status: "suspended" },
      { idempotencyKey: "k", subject: "owner-1" }
    );

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      agent_identity_id: "pai_1",
      status: "suspended",
      updated_at: "2026-08-01T00:00:00.000Z"
    });

    await expect(platform.getIdentity("pai_1")).resolves.toMatchObject({
      body: { status: "suspended" }
    });
  });

  it("blocks a lifecycle transition the policy refuses", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord({ status: "terminated" }), {});

    const platform = createAepPlatform(
      platformOptions({
        identityStore: store,
        lifecyclePolicy: {
          canSign: () => true,
          canTransition: () => false,
          canVerify: () => true
        }
      })
    );

    await expect(
      platform.updateIdentity(
        "pai_1",
        { status: "active" },
        { idempotencyKey: "k", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "identity_terminated" }, status: 403 });
  });
});

describe("hosted verification rejects everything it cannot positively confirm", () => {
  async function verifyWith(
    overrides: Partial<CreateAepPlatformOptions>,
    body: Record<string, unknown>
  ) {
    const platform = createAepPlatform(platformOptions(overrides));

    return platform.verify(body, { idempotencyKey: `k-${Math.random()}`, subject: "owner-1" });
  }

  it("reports not_recognized for an undecodable assertion", async () => {
    const response = await verifyWith(
      {},
      { client_assertion: "not-a-jwt", op: "enroll", service_did: SERVICE_DID }
    );

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ reason: "not_recognized", verified: false });
  });

  it("reports not_recognized when iss and sub disagree", async () => {
    const assertion = unsignedAssertion({
      exp: 4_000_000_000,
      iss: AGENT_DID,
      jti: "j",
      sub: "did:web:someone.else"
    });

    await expect(
      verifyWith({}, { client_assertion: assertion, op: "enroll", service_did: SERVICE_DID })
    ).resolves.toMatchObject({ body: { reason: "not_recognized", verified: false } });
  });

  it("reports not_recognized for an unknown identity, a mismatched service, and a denied caller", async () => {
    const assertion = unsignedAssertion({
      exp: 4_000_000_000,
      iss: AGENT_DID,
      jti: "j",
      sub: AGENT_DID
    });
    const populated = memoryIdentityStore();
    await populated.create(identityRecord(), {});

    await expect(
      verifyWith({}, { client_assertion: assertion, op: "enroll", service_did: SERVICE_DID })
    ).resolves.toMatchObject({ body: { verified: false } });

    await expect(
      verifyWith(
        { identityStore: populated },
        { client_assertion: assertion, op: "enroll", service_did: "did:web:other.example" }
      )
    ).resolves.toMatchObject({ body: { verified: false } });

    await expect(
      verifyWith(
        { authorizer: { authorize: () => false }, identityStore: populated },
        { client_assertion: assertion, op: "enroll", service_did: SERVICE_DID }
      )
    ).resolves.toMatchObject({ body: { verified: false } });

    await expect(
      verifyWith(
        {
          identityStore: populated,
          lifecyclePolicy: {
            canSign: () => true,
            canTransition: () => true,
            canVerify: () => false
          }
        },
        { client_assertion: assertion, op: "enroll", service_did: SERVICE_DID }
      )
    ).resolves.toMatchObject({ body: { verified: false } });
  });

  it("reports not_recognized for a bad op and a non-integer exp", async () => {
    await expect(
      verifyWith({}, { client_assertion: "a.b.c", op: "inspect", service_did: SERVICE_DID })
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });

    const badExp = unsignedAssertion({ exp: "soon", iss: AGENT_DID, jti: "j", sub: AGENT_DID });

    await expect(
      verifyWith({}, { client_assertion: badExp, op: "enroll", service_did: SERVICE_DID })
    ).resolves.toMatchObject({ body: { reason: "not_recognized", verified: false }, status: 200 });
  });

  it.each([0, 30, 31, 3600])(
    "checks issuance time with %s seconds of clock skew",
    async (offset) => {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const now = new Date("2026-08-01T00:00:00Z");
      const store = memoryIdentityStore();
      await store.create(identityRecord(), {});
      const platform = createAepPlatform(
        platformOptions({
          clock: () => now,
          identityStore: store,
          keyStore: { ...stubKeyStore(), verificationKey: () => publicKey }
        })
      );
      const clientAssertion = await signPlatformClientAssertion({
        command: "enroll",
        identity: managedIdentity(),
        jti: "clock-check",
        serviceDid: SERVICE_DID,
        signer: createJwtPlatformDelegatedSigner({ key: privateKey }),
        signingAlgorithms: ["EdDSA"],
        issuedAt: new Date(now.getTime() + offset * 1000)
      });
      await expect(
        platform.verify(
          { client_assertion: clientAssertion, op: "enroll", service_did: SERVICE_DID },
          { idempotencyKey: "clock-check", subject: "owner-1" }
        )
      ).resolves.toMatchObject({ body: { verified: offset <= 30 } });
    }
  );

  it("verifies a genuine assertion and then refuses its replay", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        identityStore: store,
        keyStore: {
          ...stubKeyStore(),
          verificationKey: () => publicKey
        },
        replayStore: memoryReplayStore()
      })
    );

    const clientAssertion = await signPlatformClientAssertion({
      command: "enroll",
      identity: managedIdentity(),
      jti: "jti-replay",
      serviceDid: SERVICE_DID,
      signer: createJwtPlatformDelegatedSigner({ key: privateKey }),
      signingAlgorithms: ["EdDSA"]
    });

    const first = await platform.verify(
      { client_assertion: clientAssertion, op: "enroll", service_did: SERVICE_DID },
      { idempotencyKey: "verify-1", subject: "owner-1" }
    );

    expect(first.body).toMatchObject({
      agent_did: AGENT_DID,
      agent_identity_id: "pai_1",
      op: "enroll",
      reason: "verified",
      status: "active",
      verified: true
    });

    const replay = await platform.verify(
      { client_assertion: clientAssertion, op: "enroll", service_did: SERVICE_DID },
      { idempotencyKey: "verify-2", subject: "owner-1" }
    );

    expect(replay.body).toMatchObject({ reason: "not_recognized", verified: false });
  });

  it("refuses an assertion whose op or resource does not match the request", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        identityStore: store,
        keyStore: { ...stubKeyStore(), verificationKey: () => publicKey },
        replayStore: memoryReplayStore()
      })
    );

    const enrollAssertion = await signPlatformClientAssertion({
      command: "enroll",
      identity: managedIdentity(),
      jti: "jti-op",
      serviceDid: SERVICE_DID,
      signer: createJwtPlatformDelegatedSigner({ key: privateKey }),
      signingAlgorithms: ["EdDSA"]
    });

    await expect(
      platform.verify(
        { client_assertion: enrollAssertion, op: "status", service_did: SERVICE_DID },
        { idempotencyKey: "verify-op", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { reason: "not_recognized", verified: false } });

    const authenticateAssertion = await signPlatformClientAssertion({
      command: "authenticate",
      identity: managedIdentity(),
      jti: "jti-res",
      resource: "https://api.service.example/orders",
      serviceDid: SERVICE_DID,
      signer: createJwtPlatformDelegatedSigner({ key: privateKey }),
      signingAlgorithms: ["EdDSA"]
    });

    await expect(
      platform.verify(
        {
          client_assertion: authenticateAssertion,
          op: "authenticate",
          resource: "https://api.service.example/other",
          service_did: SERVICE_DID
        },
        { idempotencyKey: "verify-res", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { reason: "not_recognized", verified: false } });
  });
});

describe("the sign path produces a conformant completed response", () => {
  it("signs, caps the lifetime, and echoes opaque platform context", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        clock: () => new Date("2026-07-06T12:00:00.000Z"),
        identityStore: store,
        keyStore: {
          ...stubKeyStore(),
          sign(identity, claims) {
            return createJwtPlatformDelegatedSigner({ key: privateKey })(claims, {
              identity: managedIdentity(),
              signingAlgorithms: identity.signingAlgorithms
            });
          }
        }
      })
    );

    const response = await platform.sign(
      "pai_1",
      {
        jti: "jti-sign",
        lifetime_seconds: "120",
        op: "enroll",
        platform_context: { trace: "opaque" },
        service_did: SERVICE_DID
      },
      { idempotencyKey: "sign-1", subject: "owner-1" }
    );

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      agent_did: AGENT_DID,
      expires_at: "2026-07-06T12:02:00.000Z",
      issued_at: "2026-07-06T12:00:00.000Z",
      jti: "jti-sign",
      platform_context: { trace: "opaque" },
      service_did: SERVICE_DID,
      status: "completed"
    });

    const claims = await verifyClientAssertionJwt(
      (response.body as { client_assertion: string }).client_assertion,
      {
        algorithms: ["EdDSA"],
        audience: SERVICE_DID,
        currentDate: new Date("2026-07-06T12:01:00.000Z"),
        key: publicKey
      }
    );

    // PLT-SIGN-004: platform_context never reaches the assertion.
    expect(claims).not.toHaveProperty("platform_context");
    expect(claims).not.toHaveProperty("trace");
    expect(claims.op).toBe("enroll");
  });

  it("carries an authenticate resource into the assertion under a shorter local maximum", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        clock: () => new Date("2026-07-06T12:00:00.000Z"),
        identityStore: store,
        keyStore: {
          ...stubKeyStore(),
          sign(identity, claims) {
            return createJwtPlatformDelegatedSigner({
              allowInsecureLoopback: false,
              key: privateKey
            })(claims, {
              identity: managedIdentity(),
              signingAlgorithms: identity.signingAlgorithms
            });
          }
        },
        defaultLifetimeSeconds: 60,
        maxLifetimeSeconds: 60
      })
    );

    const response = await platform.sign(
      "pai_1",
      {
        jti: "jti-authenticate",
        op: "authenticate",
        resource: "https://api.service.example/orders",
        service_did: SERVICE_DID
      },
      { idempotencyKey: "sign-auth", subject: "owner-1" }
    );

    expect(response.status).toBe(200);
    // The configured 60-second maximum lowers the default 300-second lifetime.
    expect(response.body).toMatchObject({ expires_at: "2026-07-06T12:01:00.000Z" });

    const claims = await verifyClientAssertionJwt(
      (response.body as { client_assertion: string }).client_assertion,
      {
        algorithms: ["EdDSA"],
        audience: SERVICE_DID,
        currentDate: new Date("2026-07-06T12:00:30.000Z"),
        key: publicKey
      }
    );

    expect(claims).toMatchObject({
      op: "authenticate",
      resource: "https://api.service.example/orders"
    });
  });

  it("lets a sign handler answer with a pending response", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        identityStore: store,
        signHandler({ request }) {
          if (request.op !== "enroll") return undefined;

          return {
            body: createPlatformSignPendingResponse({
              platformContext: { continuation: "opaque" },
              retryAfterSeconds: 5
            }),
            contentType: "application/aep+json",
            status: 202
          };
        }
      })
    );

    const response = await platform.sign(
      "pai_1",
      { jti: "jti-pending", op: "enroll", service_did: SERVICE_DID },
      { idempotencyKey: "sign-pending", subject: "owner-1" }
    );

    expect(response.status).toBe(202);
    expect(response.body).toMatchObject({
      platform_context: { continuation: "opaque" },
      retry_after_seconds: "5",
      status: "pending"
    });
    // PLT-SIGN-017: the contract carries no HTTP Retry-After header.
    expect(response).not.toHaveProperty("headers");
  });

  it("falls through when the sign handler declines", async () => {
    const store = memoryIdentityStore();
    await store.create(identityRecord(), {});

    const platform = createAepPlatform(
      platformOptions({
        identityStore: store,
        signHandler: () => undefined
      })
    );

    await expect(
      platform.sign(
        "pai_1",
        { jti: "jti-fallthrough", op: "enroll", service_did: SERVICE_DID },
        { idempotencyKey: "sign-through", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ status: 200 });
  });

  it("bounds the pending retry hint to 1..300", () => {
    for (const retryAfterSeconds of [0, 301, 1.5]) {
      expect(() => createPlatformSignPendingResponse({ retryAfterSeconds })).toThrow(RangeError);
    }

    expect(createPlatformSignPendingResponse({ retryAfterSeconds: 300 })).toEqual({
      retry_after_seconds: "300",
      status: "pending"
    });
  });
});

describe("provisioning and listing", () => {
  it("provisions, replays, reports the DID document, and lists", async () => {
    const store = memoryIdentityStore();
    const platform = createAepPlatform(
      platformOptions({
        agentDidIdGenerator: () => "agentdid001",
        clock: () => new Date("2026-07-06T12:00:00.000Z"),
        idGenerator: () => "pai_fixed",
        identityStore: store
      })
    );

    const provisioned = await platform.provision(
      { service_did: SERVICE_DID },
      { idempotencyKey: "prov-1", subject: "owner-1" }
    );

    expect(provisioned.status).toBe(200);
    expect(provisioned.body).toMatchObject({
      agent_did: "did:web:platform.example:agents:agentdid001",
      agent_identity_id: "pai_fixed",
      did_document_url: "https://platform.example/agents/agentdid001/did.json",
      key_id: "did:web:platform.example:agents:agentdid001",
      service_did: SERVICE_DID,
      status: "active"
    });

    // A second key for the same Service returns the existing identity, not a duplicate.
    await expect(
      platform.provision(
        { service_did: SERVICE_DID },
        { idempotencyKey: "prov-2", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { agent_identity_id: "pai_fixed" }, status: 200 });

    const didDocument = await platform.getDidDocument("pai_fixed");
    expect(didDocument.status).toBe(200);
    expect((didDocument.body as { id: string }).id).toBe(
      "did:web:platform.example:agents:agentdid001"
    );

    const listed = await platform.list({}, { subject: "owner-1" });
    expect(listed.body).toMatchObject({ count: "1", total: "1" });

    const identity = await platform.getIdentity("pai_fixed");
    expect(identity.status).toBe(200);

    const discovery = platform.discovery();
    expect(discovery.status).toBe(200);
    expect(discovery.body.signing.default_lifetime_seconds).toBe("300");
  });

  it("prefixes a generated id that does not already carry the pai_ prefix", async () => {
    const store = memoryIdentityStore();
    const platform = createAepPlatform(
      platformOptions({ idGenerator: () => "raw000", identityStore: store })
    );

    await expect(
      platform.provision({ service_did: SERVICE_DID }, { idempotencyKey: "p", subject: "owner-1" })
    ).resolves.toMatchObject({ body: { agent_identity_id: "pai_raw000" } });
  });

  it("refuses a service DID that is not a DID or cannot be resolved", async () => {
    const platform = createAepPlatform(platformOptions());

    await expect(
      platform.provision(
        { service_did: "https://api.service.example" },
        {
          idempotencyKey: "p1",
          subject: "owner-1"
        }
      )
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });

    const unresolvable = createAepPlatform(
      platformOptions({ serviceDidResolver: { resolve: () => false } })
    );

    await expect(
      unresolvable.provision(
        { service_did: SERVICE_DID },
        {
          idempotencyKey: "p2",
          subject: "owner-1"
        }
      )
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });
  });

  it("refuses an empty generated identifier", async () => {
    const platform = createAepPlatform(platformOptions({ idGenerator: () => "  " }));

    await expect(
      platform.provision({ service_did: SERVICE_DID }, { idempotencyKey: "p", subject: "owner-1" })
    ).rejects.toThrow(/non-empty string/u);

    const noAgentDid = createAepPlatform(platformOptions({ agentDidIdGenerator: () => "" }));

    await expect(
      noAgentDid.provision(
        { service_did: SERVICE_DID },
        { idempotencyKey: "p", subject: "owner-1" }
      )
    ).rejects.toThrow(/non-empty string/u);
  });

  it("uses crypto.randomUUID when no id generator is supplied", async () => {
    const store = memoryIdentityStore();
    const platform = createAepPlatform(platformOptions({ identityStore: store }));

    const response = await platform.provision(
      { service_did: SERVICE_DID },
      { idempotencyKey: "p", subject: "owner-1" }
    );

    expect((response.body as { agent_identity_id: string }).agent_identity_id).toMatch(
      /^pai_[0-9a-f]{32}$/u
    );
  });

  it("rejects DID URL templates inconsistent with the generated DID", () => {
    expect(() =>
      createAepPlatform(platformOptions({ didUrlTemplate: "https://platform.example/did.json" }))
    ).toThrow(/must include/u);

    expect(() =>
      createAepPlatform(
        platformOptions({
          agentDidIdGenerator: () => "id-1",
          didUrlTemplate: "https://platform.example/{agent_did_id}/{agent_did_id}/did.json",
          idGenerator: () => "pai_x"
        })
      )
    ).toThrow(/must match/u);
  });

  it("accepts a matching custom DID path", async () => {
    const platform = createAepPlatform(
      platformOptions({
        didPathPrefix: "identities/agents",
        didUrlTemplate: "https://platform.example/identities/agents/{agent_did_id}/did.json",
        agentDidIdGenerator: () => "abc"
      })
    );

    await expect(
      platform.provision({ service_did: SERVICE_DID }, { idempotencyKey: "p", subject: "owner-1" })
    ).resolves.toMatchObject({
      body: {
        agent_did: "did:web:platform.example:identities:agents:abc",
        did_document_url: "https://platform.example/identities/agents/abc/did.json"
      }
    });
  });
});

describe("value builders", () => {
  it("builds Service-scoped Agent DIDs with encoded components", () => {
    expect(createServiceScopedAgentDid({ agentDidId: "a b", host: "platform.example:8443" })).toBe(
      "did:web:platform.example%3A8443:agents:a%20b"
    );

    expect(
      createServiceScopedAgentDid({
        agentDidId: "abc",
        host: "platform.example",
        pathPrefix: "/tenants/one/"
      })
    ).toBe("did:web:platform.example:tenants:one:abc");

    expect(() => createServiceScopedAgentDid({ agentDidId: " ", host: "h" })).toThrow(
      /non-empty string/u
    );
    expect(() => createServiceScopedAgentDid({ agentDidId: "a", host: " " })).toThrow(
      /non-empty string/u
    );
  });

  it("derives a DID document URL when none is given", () => {
    const identity = createPlatformAgentIdentity({
      agentDid: AGENT_DID,
      agentIdentityId: "pai_1",
      clock: () => new Date("2026-01-01T00:00:00.000Z"),
      serviceDid: SERVICE_DID,
      signingAlgorithms: ["EdDSA"]
    });

    expect(identity.did_document_url).toBe("https://platform.example/agents/abc/did.json");
    expect(identity.key_id).toBe(AGENT_DID);
    expect(identity.status).toBe("active");

    expect(() =>
      createPlatformAgentIdentity({
        agentDid: AGENT_DID,
        agentIdentityId: "pai_1",
        serviceDid: SERVICE_DID,
        signingAlgorithms: []
      })
    ).toThrow(/at least one algorithm/u);
    expect(() =>
      createPlatformAgentIdentity({
        agentDid: " ",
        agentIdentityId: "pai_1",
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      })
    ).toThrow(/non-empty string/u);
  });

  it("refuses a list response whose total omits returned identities", () => {
    const identity = createPlatformAgentIdentity({
      agentDid: AGENT_DID,
      agentIdentityId: "pai_1",
      serviceDid: SERVICE_DID,
      signingAlgorithms: ["EdDSA"]
    });

    expect(() => createPlatformAgentIdentityListResponse([identity], 0)).toThrow(
      /must include every returned identity/u
    );
    expect(() => createPlatformAgentIdentityListResponse([identity], 1.5)).toThrow(TypeError);
    expect(createPlatformAgentIdentityListResponse([identity])).toMatchObject({
      count: "1",
      total: "1"
    });
  });

  it("requires resource exactly for authenticate assertions", () => {
    expect(() =>
      createPlatformClientAssertionClaims({
        command: "authenticate",
        identity: managedIdentity(),
        jti: "j",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/resource is required only for authenticate/u);

    expect(() =>
      createPlatformClientAssertionClaims({
        command: "enroll",
        identity: managedIdentity(),
        jti: "j",
        resource: "https://api.service.example/x",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/resource is required only for authenticate/u);

    expect(() =>
      createPlatformClientAssertionClaims({
        command: "enroll",
        identity: managedIdentity(),
        issuedAt: -1,
        jti: "j",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/non-negative epoch second/u);

    expect(() =>
      createPlatformClientAssertionClaims({
        command: "enroll",
        identity: managedIdentity(),
        jti: "  ",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/non-empty string/u);
  });

  it("refuses Enroll and sign builders for identities that are not active", () => {
    expect(() =>
      createPlatformEnrollRequest({ identity: managedIdentity("revoked"), idempotencyKey: "k" })
    ).toThrow(/not active/u);

    expect(() =>
      createPlatformEnrollRequest({ identity: managedIdentity(), idempotencyKey: "  " })
    ).toThrow(/non-empty string/u);

    expect(
      createPlatformEnrollRequest({
        claims: { "agent.name": "Example" },
        identity: managedIdentity(),
        idempotencyKey: "k"
      })
    ).toEqual({
      agent_did: AGENT_DID,
      claims: { "agent.name": "Example" },
      idempotency_key: "k"
    });

    expect(
      createPlatformEnrollRequest({ identity: managedIdentity(), idempotencyKey: "k" })
    ).toEqual({ agent_did: AGENT_DID, idempotency_key: "k" });

    expect(() =>
      createPlatformSignResponse({
        clientAssertion: "  ",
        identity: managedIdentity(),
        jti: "j",
        serviceDid: SERVICE_DID
      })
    ).toThrow(/non-empty string/u);

    // With no lifetime given the builder falls back to the 300-second default.
    expect(
      createPlatformSignResponse({
        clientAssertion: "a.b.c",
        identity: managedIdentity(),
        issuedAt: new Date("2026-07-06T12:00:00.000Z"),
        jti: "j",
        serviceDid: SERVICE_DID
      })
    ).toMatchObject({
      expires_at: "2026-07-06T12:05:00.000Z",
      issued_at: "2026-07-06T12:00:00.000Z"
    });
  });

  it("refuses a delegated signer with no AEP algorithm available", async () => {
    await expect(
      signPlatformClientAssertion({
        command: "enroll",
        identity: managedIdentity(),
        jti: "j",
        serviceDid: SERVICE_DID,
        signer: createJwtPlatformDelegatedSigner({
          key: generateKeyPairSync("ed25519").privateKey
        }),
        signingAlgorithms: []
      })
    ).rejects.toThrow(/No supported AEP JOSE signing algorithm/u);
  });
});

describe("InMemoryManagedAgentRegistry", () => {
  it("filters, mutates, and removes managed identities", () => {
    const registry = new InMemoryManagedAgentRegistry([
      createManagedAgentIdentity({ accountId: "acct-1", agentDid: "did:web:a", tenantId: "t-1" }),
      createManagedAgentIdentity({ accountId: "acct-2", agentDid: "did:web:b", tenantId: "t-2" })
    ]);

    expect(registry.list()).toHaveLength(2);
    expect(registry.list({ accountId: "acct-1" })).toHaveLength(1);
    expect(registry.list({ tenantId: "t-2" })).toHaveLength(1);
    expect(registry.list({ status: "revoked" })).toHaveLength(0);

    expect(registry.get("did:web:a")?.agentDid).toBe("did:web:a");
    expect(registry.get("did:web:missing")).toBeUndefined();

    expect(registry.setStatus("did:web:a", "suspended").status).toBe("suspended");
    expect(registry.list({ status: "suspended" })).toHaveLength(1);
    expect(() => registry.setStatus("did:web:missing", "revoked")).toThrow(/not found/u);

    expect(registry.remove("did:web:b")).toBe(true);
    expect(registry.remove("did:web:b")).toBe(false);
    expect(registry.list()).toHaveLength(1);

    expect(() => registry.upsert(createManagedAgentIdentity({ agentDid: "x" }))).not.toThrow();
  });

  it("updates managed identity metadata without mutating the input", () => {
    const identity = createManagedAgentIdentity({
      agentDid: AGENT_DID,
      clock: () => new Date("2026-01-01T00:00:00.000Z"),
      metadata: { a: 1 }
    });

    const updated = updateManagedAgentIdentity(
      identity,
      { metadata: { b: 2 }, status: "suspended" },
      () => new Date("2026-02-01T00:00:00.000Z")
    );

    expect(updated).toMatchObject({
      metadata: { a: 1, b: 2 },
      status: "suspended",
      updatedAt: "2026-02-01T00:00:00.000Z"
    });
    expect(identity.metadata).toEqual({ a: 1 });

    const untouched = updateManagedAgentIdentity(identity, {});
    expect(untouched.metadata).toEqual({ a: 1 });
    expect(untouched.status).toBe("active");
  });
});

describe("Platform review regressions", () => {
  it("executes concurrent provisioning once and rejects concurrent changed input", async () => {
    const create = vi.fn();
    const platform = createAepPlatform(
      platformOptions({ keyStore: { ...stubKeyStore(), create } })
    );
    const context = { subject: "owner", idempotencyKey: "shared" };
    const [first, retry, conflict] = await Promise.all([
      platform.provision({ service_did: SERVICE_DID }, context),
      platform.provision({ service_did: SERVICE_DID }, context),
      platform.provision({ service_did: "did:web:other.example" }, context)
    ]);
    expect(first.status).toBe(200);
    expect(retry).toEqual(first);
    expect(conflict).toMatchObject({ status: 409, body: { code: "idempotency_conflict" } });
    expect(create).toHaveBeenCalledTimes(1);
  });

  it("releases waiting retries after a failed execution without caching the failure", async () => {
    const create = vi
      .fn()
      .mockRejectedValueOnce(new Error("key store unavailable"))
      .mockResolvedValue(undefined);
    const platform = createAepPlatform(
      platformOptions({ keyStore: { ...stubKeyStore(), create } })
    );
    const context = { subject: "owner", idempotencyKey: "shared" };
    const results = await Promise.allSettled([
      platform.provision({ service_did: SERVICE_DID }, context),
      platform.provision({ service_did: SERVICE_DID }, context)
    ]);
    expect(results[0]).toMatchObject({
      status: "rejected",
      reason: new Error("key store unavailable")
    });
    expect(results[1]).toMatchObject({ status: "fulfilled", value: { status: 200 } });
    expect(create).toHaveBeenCalledTimes(2);
  });

  it("authorizes cached provision and sign retries without re-signing", async () => {
    let allowed = true;
    const identityStore = memoryIdentityStore();
    await identityStore.create(identityRecord(), {});
    const authorize = vi.fn(() => allowed);
    const sign = vi.fn(() => "a.b.c");
    const platform = createAepPlatform(
      platformOptions({
        authorizer: { authorize },
        identityStore,
        keyStore: { ...stubKeyStore(), sign }
      })
    );
    const context = { subject: "owner", idempotencyKey: "provision" };
    const request = { jti: "same", op: "enroll", service_did: SERVICE_DID };
    const first = await platform.provision({ service_did: SERVICE_DID }, context);
    const signed = await platform.sign("pai_1", request, { ...context, idempotencyKey: "sign" });
    expect(await platform.sign("pai_1", request, { ...context, idempotencyKey: "sign" })).toEqual(
      signed
    );
    allowed = false;
    expect(first.status).toBe(200);
    expect(await platform.provision({ service_did: SERVICE_DID }, context)).toMatchObject({
      status: 404
    });
    expect(
      await platform.sign("pai_1", request, { ...context, idempotencyKey: "sign" })
    ).toMatchObject({ status: 404 });
    expect(authorize).toHaveBeenCalledTimes(5);
    expect(sign).toHaveBeenCalledTimes(1);
  });

  it("preserves pending results and retains them for an hour after completion", async () => {
    let now = new Date("2026-01-01T00:00:00Z");
    const identities = memoryIdentityStore();
    await identities.create(identityRecord(), {});
    const records: PlatformIdempotencyRecord[] = [];
    const signHandler = vi.fn(() => {
      now = new Date("2026-01-01T00:02:00Z");
      return {
        status: 202,
        contentType: "application/aep+json",
        body: createPlatformSignPendingResponse({
          retryAfterSeconds: 5,
          platformContext: { approval: "pending" }
        })
      };
    });
    const platform = createAepPlatform(
      platformOptions({
        identityStore: identities,
        clock: () => now,
        idempotencyStore: recordingIdempotencyStore(records),
        signHandler
      })
    );
    const request = { jti: "pending", op: "enroll", service_did: SERVICE_DID };
    const context = { subject: "owner", idempotencyKey: "pending" };
    const [first, retry] = await Promise.all([
      platform.sign("pai_1", request, context),
      platform.sign("pai_1", request, context)
    ]);
    expect(first.status).toBe(202);
    expect(retry).toEqual(first);
    expect(signHandler).toHaveBeenCalledTimes(1);
    expect(records[0]?.expiresAt).toBe("2026-01-01T01:02:00.000Z");
  });

  it.each(["1e2", "0x10", " 60 ", "01", "1.5", "0"])(
    "rejects nondecimal lifetime %s before signing",
    async (lifetime_seconds) => {
      const sign = vi.fn();
      const platform = createAepPlatform(
        platformOptions({ keyStore: { ...stubKeyStore(), sign } })
      );
      expect(
        await platform.sign(
          "pai_1",
          { jti: "lifetime", op: "enroll", service_did: SERVICE_DID, lifetime_seconds },
          { subject: "owner", idempotencyKey: "lifetime" }
        )
      ).toMatchObject({ status: 400, body: { code: "invalid_request" } });
      expect(sign).not.toHaveBeenCalled();
    }
  );

  it("enforces a shorter local maximum before a custom handler", async () => {
    const identities = memoryIdentityStore();
    await identities.create(identityRecord(), {});
    const signHandler = vi.fn();
    const platform = createAepPlatform(
      platformOptions({
        identityStore: identities,
        defaultLifetimeSeconds: 60,
        maxLifetimeSeconds: 60,
        signHandler
      })
    );
    const request = { jti: "lifetime", op: "enroll", service_did: SERVICE_DID };
    expect(
      await platform.sign(
        "pai_1",
        { ...request, lifetime_seconds: "120" },
        { subject: "owner", idempotencyKey: "large" }
      )
    ).toMatchObject({ status: 400 });
    expect(signHandler).not.toHaveBeenCalled();
    expect(
      await platform.sign(
        "pai_1",
        { ...request, lifetime_seconds: "60" },
        { subject: "owner", idempotencyKey: "valid" }
      )
    ).toMatchObject({ status: 200 });
  });

  it.each(["suspended", "revoked", "terminated"] as const)(
    "does not publish or sign a %s identity through permissive callbacks",
    async (status) => {
      const identities = memoryIdentityStore();
      await identities.create(identityRecord({ status }), {});
      const signHandler = vi.fn();
      const didVerificationMethod = vi.fn();
      const platform = createAepPlatform(
        platformOptions({
          identityStore: identities,
          keyStore: { ...stubKeyStore(), didVerificationMethod },
          signHandler,
          lifecyclePolicy: { canSign: () => true, canVerify: () => true, canTransition: () => true }
        })
      );
      expect(await platform.getDidDocument("pai_1")).toMatchObject({ status: 404 });
      expect(
        await platform.sign(
          "pai_1",
          { jti: "inactive", op: "enroll", service_did: SERVICE_DID },
          { subject: "owner", idempotencyKey: "inactive" }
        )
      ).toMatchObject({ status: 403 });
      expect(signHandler).not.toHaveBeenCalled();
      expect(didVerificationMethod).not.toHaveBeenCalled();
    }
  );

  it("verifies real signatures, rejects fragments and inactive identities, and reauthorizes cached results", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const identities = memoryIdentityStore();
    await identities.create(identityRecord(), {});
    let allowed = true;
    const consume = vi.fn(() => true);
    const platform = createAepPlatform(
      platformOptions({
        identityStore: identities,
        authorizer: { authorize: () => allowed },
        keyStore: { ...stubKeyStore(), verificationKey: () => publicKey },
        replayStore: { consume },
        lifecyclePolicy: { canSign: () => true, canVerify: () => true, canTransition: () => true }
      })
    );
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: AGENT_DID,
      sub: AGENT_DID,
      aud: SERVICE_DID,
      iat: now,
      exp: now + 60,
      jti: "verified",
      op: "enroll" as const
    };
    const token = await signClientAssertionJwt(claims, { alg: "EdDSA", key: privateKey });
    const fragmented = await signClientAssertionJwt(
      { ...claims, jti: "fragment" },
      { alg: "EdDSA", key: privateKey, kid: AGENT_DID + "#key" }
    );
    const request = { client_assertion: token, op: "enroll", service_did: SERVICE_DID };
    const context = { subject: "owner", idempotencyKey: "verify" };
    const verified = await platform.verify(request, context);
    expect(verified.body).toMatchObject({ verified: true });
    expect(await platform.verify(request, context)).toEqual(verified);
    expect(consume).toHaveBeenCalledTimes(1);
    expect(
      (
        await platform.verify(
          { ...request, client_assertion: fragmented },
          { ...context, idempotencyKey: "fragment" }
        )
      ).body
    ).toMatchObject({ verified: false });
    allowed = false;
    expect((await platform.verify(request, context)).body).toMatchObject({ verified: false });
    allowed = true;
    await identities.update(
      "pai_1",
      { status: "suspended", updatedAt: new Date().toISOString() },
      {}
    );
    expect(
      (await platform.verify(request, { ...context, idempotencyKey: "suspended" })).body
    ).toMatchObject({ verified: false });
    expect(consume).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------- test doubles

function identityRecord(overrides: Partial<PlatformIdentityRecord> = {}): PlatformIdentityRecord {
  return {
    agentDid: AGENT_DID,
    agentDidId: "abc",
    agentIdentityId: "pai_1",
    createdAt: "2026-01-01T00:00:00.000Z",
    didDocumentUrl: "https://platform.example/agents/abc/did.json",
    keyId: AGENT_DID,
    serviceDid: SERVICE_DID,
    signingAlgorithms: ["EdDSA"],
    status: "active",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides
  };
}

function memoryIdentityStore(): PlatformIdentityStore {
  const identities = new Map<string, PlatformIdentityRecord>();
  const clone = (identity: PlatformIdentityRecord) => ({
    ...identity,
    signingAlgorithms: [...identity.signingAlgorithms]
  });

  return {
    create(identity) {
      identities.set(identity.agentIdentityId, clone(identity));
    },
    findByAgentDid(agentDid) {
      return [...identities.values()].map(clone).find((item) => item.agentDid === agentDid);
    },
    findByServiceDid(serviceDid) {
      return [...identities.values()].map(clone).find((item) => item.serviceDid === serviceDid);
    },
    get(agentIdentityId) {
      const identity = identities.get(agentIdentityId);

      return identity === undefined ? undefined : clone(identity);
    },
    list() {
      return { identities: [...identities.values()].map(clone), total: identities.size };
    },
    update(agentIdentityId, update) {
      const identity = identities.get(agentIdentityId);

      if (identity === undefined) return undefined;

      const updated = { ...identity, ...update };
      identities.set(agentIdentityId, updated);
      return clone(updated);
    }
  };
}

function memoryIdempotencyStore(): PlatformIdempotencyStore {
  return createInMemoryPlatformIdempotencyStore();
}

function recordingIdempotencyStore(sink: PlatformIdempotencyRecord[]): PlatformIdempotencyStore {
  const store = createInMemoryPlatformIdempotencyStore();
  return {
    execute(input, execute, context) {
      return store.execute(
        input,
        async () => {
          const record = await execute();
          sink.push(structuredClone(record));
          return record;
        },
        context
      );
    }
  };
}

function memoryReplayStore(): PlatformReplayStore {
  const seen = new Set<string>();

  return {
    consume(key) {
      if (seen.has(key)) return false;

      seen.add(key);
      return true;
    }
  };
}

function stubKeyStore() {
  return {
    create() {
      return undefined;
    },
    didVerificationMethod() {
      return { publicKeyJwk: { kty: "OKP" }, type: "JsonWebKey2020" };
    },
    sign() {
      return "a.b.c";
    },
    verificationKey() {
      return {} as never;
    }
  };
}

function platformOptions(
  overrides: Partial<CreateAepPlatformOptions> = {}
): CreateAepPlatformOptions {
  return {
    authorizer: { authorize: () => true },
    didHost: "platform.example",
    didUrlTemplate: "https://platform.example/agents/{agent_did_id}/did.json",
    discovery: {
      endpointBase: "/v1/aep",
      endpoints: {
        lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
        list: "/v1/aep/agent-identities",
        provision: "/v1/aep/agent-identities",
        sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
      },
      platformName: "Example Platform"
    },
    idempotencyStore: memoryIdempotencyStore(),
    identityStore: memoryIdentityStore(),
    keyStore: stubKeyStore(),
    replayStore: memoryReplayStore(),
    serviceDidResolver: { resolve: () => true },
    signingAlgorithms: ["EdDSA"],
    ...overrides
  };
}

function unsignedAssertion(payload: Record<string, unknown>): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

  return `${encode({ alg: "EdDSA", kid: AGENT_DID, typ: "JWT" })}.${encode(payload)}.signature`;
}
