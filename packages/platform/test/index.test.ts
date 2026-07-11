import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";

import { verifyClientAssertionJwt } from "@aep-foundation/core";

import {
  InMemoryManagedAgentRegistry,
  createAepPlatform,
  createPlatformAgentIdentityListResponse,
  createPlatformAgentIdentity,
  createManagedAgentIdentity,
  createPlatformDiscoveryDocument,
  createPlatformLifecycleRequest,
  createPlatformProvisionRequest,
  createPlatformSignRequest,
  createPlatformSignPendingResponse,
  createPlatformSignResponse,
  createPlatformVerificationRequest,
  createPlatformVerificationResponse,
  createJwtPlatformDelegatedSigner,
  createManagedAgentDidDocument,
  createPlatformClientAssertionClaims,
  createPlatformEnrollRequest,
  createServiceScopedAgentDid,
  packageName,
  platformHostedIdentityDraft,
  publishManagedAgentDidDocument,
  signPlatformClientAssertion,
  updateManagedAgentIdentity
} from "../src/index.js";
import type {
  PlatformIdentityRecord,
  PlatformIdentityStore,
  PlatformIdempotencyRecord,
  PlatformIdempotencyStore,
  PlatformReplayStore
} from "../src/index.js";

describe("@aep-foundation/platform", () => {
  it("exports the package name", () => {
    expect(packageName).toBe("@aep-foundation/platform");
  });

  it("exports the Platform Hosted Identity draft name", () => {
    expect(platformHostedIdentityDraft).toBe("draft-kavian-aep-platform-hosted-identity-00");
  });

  it("builds Platform discovery documents", () => {
    expect(
      createPlatformDiscoveryDocument({
        didUrlTemplate: "https://platform.example.com/agents/{agent_did_id}/did.json",
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
        platformName: "Example Platform",
        signingAlgorithms: ["ES256", "EdDSA"]
      })
    ).toEqual({
      aep_version: "1.0",
      endpoints: {
        hosted_verification: "/v1/aep/verifications",
        lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
        list: "/v1/aep/agent-identities",
        provision: "/v1/aep/agent-identities",
        sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
      },
      http: {
        endpoint_base: "/v1/aep"
      },
      identity: {
        did_methods: ["did:web"],
        did_url_template: "https://platform.example.com/agents/{agent_did_id}/did.json"
      },
      platform: {
        did: "did:web:platform.example.com",
        hosted_verification: true,
        name: "Example Platform"
      },
      signing: {
        algorithms: ["ES256", "EdDSA"],
        default_lifetime_seconds: "300"
      }
    });
  });

  it("builds Service-scoped Agent DIDs", () => {
    expect(
      createServiceScopedAgentDid({
        agentDidId: "4Yf7p2xQd9",
        host: "platform.example.com",
        pathPrefix: "agents"
      })
    ).toBe("did:web:platform.example.com:agents:4Yf7p2xQd9");
  });

  it("creates managed Agent identity records", () => {
    const identity = createManagedAgentIdentity({
      accountId: "acct_123",
      agentDid: "did:web:agent.example.com:agents:123",
      clock: () => new Date("2026-01-01T00:00:00.000Z"),
      metadata: {
        label: "billing-agent"
      },
      tenantId: "tenant_123"
    });

    expect(identity).toEqual({
      accountId: "acct_123",
      agentDid: "did:web:agent.example.com:agents:123",
      createdAt: "2026-01-01T00:00:00.000Z",
      metadata: {
        label: "billing-agent"
      },
      status: "active",
      subjectDid: undefined,
      tenantId: "tenant_123",
      updatedAt: "2026-01-01T00:00:00.000Z"
    });
  });

  it("stores defensive copies in an in-memory registry", () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123",
      metadata: {
        label: "billing-agent"
      },
      tenantId: "tenant_123"
    });
    const registry = new InMemoryManagedAgentRegistry([identity]);
    const stored = registry.get(identity.agentDid);

    expect(stored).toMatchObject({
      agentDid: identity.agentDid,
      metadata: {
        label: "billing-agent"
      }
    });

    if (stored !== undefined) {
      stored.metadata["label"] = "mutated";
    }

    expect(registry.get(identity.agentDid)?.metadata).toEqual({
      label: "billing-agent"
    });
    expect(registry.list({ tenantId: "tenant_123" })).toHaveLength(1);
  });

  it("builds Platform Agent identity responses", () => {
    expect(
      createPlatformAgentIdentity({
        agentDid: "did:web:platform.example.com:agents:4Yf7p2xQd9",
        agentIdentityId: "pai_01J0AEPPLATFORM000000000001",
        clock: () => new Date("2026-07-06T12:00:00.000Z"),
        serviceDid: "did:web:api.service.example",
        signingAlgorithms: ["ES256"]
      })
    ).toEqual({
      agent_did: "did:web:platform.example.com:agents:4Yf7p2xQd9",
      agent_identity_id: "pai_01J0AEPPLATFORM000000000001",
      created_at: "2026-07-06T12:00:00.000Z",
      did_document_url: "https://platform.example.com/agents/4Yf7p2xQd9/did.json",
      key_id: "did:web:platform.example.com:agents:4Yf7p2xQd9",
      service_did: "did:web:api.service.example",
      signing_algorithms: ["ES256"],
      status: "active",
      updated_at: "2026-07-06T12:00:00.000Z"
    });
  });

  it("builds paginated Platform Agent identity list responses", () => {
    const identity = createPlatformAgentIdentity({
      agentDid: "did:web:platform.example.com:agents:4Yf7p2xQd9",
      agentIdentityId: "pai_01J0AEPPLATFORM000000000001",
      clock: () => new Date("2026-07-06T12:00:00.000Z"),
      serviceDid: "did:web:api.service.example",
      signingAlgorithms: ["ES256"]
    });

    expect(createPlatformAgentIdentityListResponse([identity], 10)).toEqual({
      count: "1",
      data: [identity],
      total: "10"
    });
  });

  it("builds Platform lifecycle update requests", () => {
    expect(createPlatformLifecycleRequest({ status: "suspended" })).toEqual({
      status: "suspended"
    });
  });

  it("updates managed Agent identity metadata and status", () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123",
      clock: () => new Date("2026-01-01T00:00:00.000Z"),
      metadata: {
        first: true
      }
    });

    const updated = updateManagedAgentIdentity(
      identity,
      {
        metadata: {
          second: true
        },
        status: "suspended"
      },
      () => new Date("2026-01-02T00:00:00.000Z")
    );

    expect(updated).toMatchObject({
      metadata: {
        first: true,
        second: true
      },
      status: "suspended",
      updatedAt: "2026-01-02T00:00:00.000Z"
    });
  });

  it("builds platform-mediated Enroll requests", () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123"
    });

    expect(
      createPlatformEnrollRequest({
        claims: {
          "contact.email": "ops@example.com"
        },
        identity,
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      })
    ).toEqual({
      agent_did: "did:web:agent.example.com:agents:123",
      claims: {
        "contact.email": "ops@example.com"
      },
      idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
    });
  });

  it("builds Platform provisioning requests", () => {
    expect(
      createPlatformProvisionRequest({
        idempotencyKey: "01J0AEPPLATFORM000000000001",
        serviceDid: "did:web:api.service.example"
      })
    ).toEqual({
      service_did: "did:web:api.service.example"
    });
  });

  it("builds baseline client assertion claims for delegated signing", () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123",
      subjectDid: "did:web:customer.example.com"
    });

    expect(
      createPlatformClientAssertionClaims({
        command: "enroll",
        identity,
        issuedAt: 1748428800,
        jti: "01J0AEPVECTORENROLL0000000001",
        serviceDid: "did:web:api.example.com"
      })
    ).toEqual({
      aud: "did:web:api.example.com",
      exp: 1748429100,
      iat: 1748428800,
      iss: "did:web:agent.example.com:agents:123",
      jti: "01J0AEPVECTORENROLL0000000001",
      op: "enroll",
      sub: "did:web:agent.example.com:agents:123"
    });
  });

  it("provisions, signs, and verifies identities through the Platform engine", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256"
    });
    const identityStore = createMemoryIdentityStore();
    const platform = createAepPlatform({
      clock: () => new Date("2026-07-06T12:00:00.000Z"),
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
      idGenerator: () => "01J0AEPPLATFORM000000000001",
      idempotencyStore: createMemoryIdempotencyStore(),
      identityStore,
      keyStore: {
        create() {
          return undefined;
        },
        didVerificationMethod(identity) {
          return {
            id: identity.keyId,
            publicKeyPem: "test-public-key",
            relationships: ["authentication", "assertionMethod"],
            type: "JsonWebKey2020"
          };
        },
        sign(identity, claims) {
          return createJwtPlatformDelegatedSigner({
            alg: "ES256",
            key: privateKey,
            kid: identity.keyId
          })(claims, {
            identity: managedIdentityFromTestRecord(identity),
            signingAlgorithms: identity.signingAlgorithms
          });
        },
        verificationKey() {
          return publicKey;
        }
      },
      replayStore: createMemoryReplayStore(),
      serviceDidResolver: {
        resolve(serviceDid) {
          return serviceDid === "did:web:api.service.example";
        }
      },
      signHandler({ request }) {
        if (request.platform_context?.["stage"] !== "pending") return undefined;
        return {
          body: createPlatformSignPendingResponse({
            platformContext: { continuation: "opaque" },
            retryAfterSeconds: 5
          }),
          contentType: "application/aep+json",
          status: 202
        };
      },
      signingAlgorithms: ["ES256"]
    });

    await expect(
      platform.provision({ service_did: "did:web:api.service.example" })
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });
    await expect(
      platform.provision(
        { service_did: "did:web:api.service.example" },
        { idempotencyKey: "missing-principal" }
      )
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });
    await expect(
      platform.provision(
        { service_did: "did:web:unknown.service.example" },
        { idempotencyKey: "unresolved-service", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });

    const provisioned = await platform.provision(
      { service_did: "did:web:api.service.example" },
      { idempotencyKey: "01J0AEPIDEMPOTENCY0000000001", subject: "owner-1" }
    );

    expect(provisioned.status).toBe(200);
    expect(provisioned.body).toMatchObject({
      agent_did: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
      agent_identity_id: "pai_01J0AEPPLATFORM000000000001",
      key_id: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
      service_did: "did:web:api.service.example"
    });

    await expect(
      platform.provision(
        { service_did: "did:web:api.service.example" },
        { idempotencyKey: "01J0AEPIDEMPOTENCY0000000001", subject: "owner-1" }
      )
    ).resolves.toEqual(provisioned);
    await expect(
      platform.provision(
        { service_did: "did:web:other.service.example" },
        { idempotencyKey: "01J0AEPIDEMPOTENCY0000000001", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "idempotency_conflict" }, status: 409 });

    const listed = await platform.list();

    expect(listed.body).toMatchObject({
      count: "1",
      total: "1"
    });

    const signed = await platform.sign(
      "pai_01J0AEPPLATFORM000000000001",
      {
        jti: "01J0AEPASSERTION0000000001",
        lifetime_seconds: "300",
        op: "enroll",
        service_did: "did:web:api.service.example"
      },
      { idempotencyKey: "01J0AEPSIGN000000000000000001", subject: "owner-1" }
    );

    expect(signed.status).toBe(200);
    expect(signed.body).toMatchObject({
      agent_did: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
      jti: "01J0AEPASSERTION0000000001"
    });

    await expect(
      platform.sign(
        "pai_01J0AEPPLATFORM000000000001",
        {
          jti: "01J0AEPASSERTION0000000001",
          lifetime_seconds: "300",
          op: "enroll",
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "01J0AEPSIGN000000000000000001", subject: "owner-1" }
      )
    ).resolves.toEqual(signed);
    await expect(
      platform.sign(
        "pai_01J0AEPPLATFORM000000000001",
        {
          jti: "changed",
          op: "enroll",
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "01J0AEPSIGN000000000000000001", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "idempotency_conflict" }, status: 409 });

    const pending = await platform.sign(
      "pai_01J0AEPPLATFORM000000000001",
      {
        jti: "01J0AEPPENDING000000000000001",
        op: "enroll",
        platform_context: { stage: "pending" },
        service_did: "did:web:api.service.example"
      },
      { idempotencyKey: "01J0AEPSIGNINITIAL0000000001", subject: "owner-1" }
    );
    expect(pending).toMatchObject({
      body: { status: "pending", retry_after_seconds: "5" },
      status: 202
    });
    await expect(
      platform.sign(
        "pai_01J0AEPPLATFORM000000000001",
        {
          jti: "01J0AEPPENDING000000000000001",
          op: "enroll",
          platform_context: { stage: "pending" },
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "01J0AEPSIGNINITIAL0000000001", subject: "owner-1" }
      )
    ).resolves.toEqual(pending);
    await expect(
      platform.sign(
        "pai_01J0AEPPLATFORM000000000001",
        {
          jti: "01J0AEPASSERTION0000000001",
          op: "enroll",
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "01J0AEPIDEMPOTENCY0000000001", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "idempotency_conflict" }, status: 409 });

    if (!("client_assertion" in signed.body)) {
      throw new Error("Expected Platform sign response.");
    }

    const verified = await platform.verify(
      {
        client_assertion: signed.body.client_assertion,
        op: "enroll",
        service_did: "did:web:api.service.example"
      },
      { idempotencyKey: "01J0AEPVERIFY000000000000001", subject: "owner-1" }
    );

    expect(verified.body).toMatchObject({
      agent_did: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
      agent_identity_id: "pai_01J0AEPPLATFORM000000000001",
      op: "enroll",
      reason: "verified",
      verified: true
    });
    await expect(
      platform.verify(
        {
          client_assertion: signed.body.client_assertion,
          op: "enroll",
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "01J0AEPVERIFY000000000000001", subject: "owner-1" }
      )
    ).resolves.toEqual(verified);
    await expect(
      platform.verify(
        {
          client_assertion: signed.body.client_assertion,
          op: "status",
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "01J0AEPVERIFY000000000000001", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "idempotency_conflict" }, status: 409 });
    await expect(
      platform.verify(
        {
          client_assertion: signed.body.client_assertion,
          op: "enroll",
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "01J0AEPVERIFY000000000000001", subject: "owner-2" }
      )
    ).resolves.toMatchObject({ body: { verified: false }, status: 200 });

    await expect(
      platform.sign(
        "pai_missing",
        {
          jti: "missing-identity",
          op: "enroll",
          service_did: "did:web:api.service.example"
        },
        { idempotencyKey: "missing-identity-key", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "not_recognized" }, status: 404 });
    await expect(
      platform.sign(
        "pai_01J0AEPPLATFORM000000000001",
        {
          jti: "wrong-service",
          op: "enroll",
          service_did: "did:web:other.service.example"
        },
        { idempotencyKey: "wrong-service-key", subject: "owner-1" }
      )
    ).resolves.toMatchObject({ body: { code: "not_recognized" }, status: 404 });
  });

  it("builds DID documents for managed Agent identities", () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123",
      subjectDid: "did:web:customer.example.com"
    });

    expect(
      createManagedAgentDidDocument({
        additionalContexts: ["https://w3id.org/security/suites/jws-2020/v1"],
        identity,
        service: [
          {
            id: "did:web:agent.example.com:agents:123#aep",
            serviceEndpoint: "https://agent.example.com/aep",
            type: "AgentEnrollmentProtocol"
          }
        ],
        verificationMethods: [
          {
            id: "did:web:agent.example.com:agents:123#key-1",
            publicKeyJwk: {
              crv: "P-256",
              kty: "EC",
              x: "x",
              y: "y"
            },
            relationships: ["authentication", "assertionMethod", "capabilityInvocation"],
            type: "JsonWebKey2020"
          }
        ]
      })
    ).toEqual({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
      assertionMethod: ["did:web:agent.example.com:agents:123#key-1"],
      authentication: ["did:web:agent.example.com:agents:123#key-1"],
      capabilityInvocation: ["did:web:agent.example.com:agents:123#key-1"],
      id: "did:web:agent.example.com:agents:123",
      service: [
        {
          id: "did:web:agent.example.com:agents:123#aep",
          serviceEndpoint: "https://agent.example.com/aep",
          type: "AgentEnrollmentProtocol"
        }
      ],
      verificationMethod: [
        {
          controller: "did:web:agent.example.com:agents:123",
          id: "did:web:agent.example.com:agents:123#key-1",
          publicKeyJwk: {
            crv: "P-256",
            kty: "EC",
            x: "x",
            y: "y"
          },
          type: "JsonWebKey2020"
        }
      ]
    });
  });

  it("publishes DID documents through caller-provided publishers", async () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123"
    });
    const publications: unknown[] = [];

    await expect(
      publishManagedAgentDidDocument({
        identity,
        publisher: {
          publish(document) {
            publications.push(document);
            return {
              document,
              publishedAt: "2026-05-28T12:00:00.000Z",
              url: "https://agent.example.com/.well-known/did.json"
            };
          }
        },
        verificationMethods: [
          {
            publicKeyMultibase: "zKey",
            type: "Multikey"
          }
        ]
      })
    ).resolves.toMatchObject({
      publishedAt: "2026-05-28T12:00:00.000Z",
      url: "https://agent.example.com/.well-known/did.json"
    });
    expect(publications).toHaveLength(1);
  });

  it("signs delegated platform client assertions with JWT keys", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256"
    });
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123"
    });
    const jwt = await signPlatformClientAssertion({
      command: "enroll",
      identity,
      issuedAt: 1779969600,
      jti: "platform-jwt",
      serviceDid: "did:web:api.example.com",
      signer: createJwtPlatformDelegatedSigner({
        alg: "ES256",
        key: privateKey
      })
    });

    await expect(
      verifyClientAssertionJwt(jwt, {
        algorithms: ["ES256"],
        audience: "did:web:api.example.com",
        currentDate: new Date("2026-05-28T12:00:00.000Z"),
        key: publicKey
      })
    ).resolves.toMatchObject({
      jti: "platform-jwt",
      op: "enroll",
      sub: "did:web:agent.example.com:agents:123"
    });
  });

  it("builds Platform delegated signing request and response bodies", () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:platform.example.com:agents:4Yf7p2xQd9"
    });

    expect(
      createPlatformSignRequest({
        command: "enroll",
        jti: "01J0AEPASSERTION0000000001",
        serviceDid: "did:web:api.service.example",
        lifetimeSeconds: 300
      })
    ).toEqual({
      jti: "01J0AEPASSERTION0000000001",
      lifetime_seconds: "300",
      op: "enroll",
      service_did: "did:web:api.service.example"
    });

    expect(
      createPlatformSignResponse({
        clientAssertion: "signed.jwt",
        identity,
        issuedAt: new Date("2026-07-06T12:00:00.000Z"),
        jti: "01J0AEPASSERTION0000000001",
        serviceDid: "did:web:api.service.example",
        lifetimeSeconds: 300
      })
    ).toEqual({
      status: "completed",
      agent_did: "did:web:platform.example.com:agents:4Yf7p2xQd9",
      client_assertion: "signed.jwt",
      expires_at: "2026-07-06T12:05:00.000Z",
      issued_at: "2026-07-06T12:00:00.000Z",
      jti: "01J0AEPASSERTION0000000001",
      service_did: "did:web:api.service.example"
    });
  });

  it("rejects delegated signing lifetime values above the configured maximum", () => {
    expect(() =>
      createPlatformSignRequest({
        command: "enroll",
        jti: "01J0AEPASSERTION0000000001",
        serviceDid: "did:web:api.service.example",
        lifetimeSeconds: 301
      })
    ).toThrow("lifetimeSeconds must not exceed maxLifetimeSeconds");
  });

  it("builds hosted verification request and rich response bodies", () => {
    expect(
      createPlatformVerificationRequest({
        clientAssertion: "signed.jwt",
        command: "enroll",
        serviceDid: "did:web:api.service.example"
      })
    ).toEqual({
      client_assertion: "signed.jwt",
      op: "enroll",
      service_did: "did:web:api.service.example"
    });

    expect(
      createPlatformVerificationResponse({
        agentDid: "did:web:platform.example.com:agents:4Yf7p2xQd9",
        agentIdentityId: "pai_01J0AEPPLATFORM000000000001",
        command: "enroll",
        reason: "verified",
        serviceDid: "did:web:api.service.example",
        status: "active",
        verified: true
      })
    ).toEqual({
      agent_did: "did:web:platform.example.com:agents:4Yf7p2xQd9",
      agent_identity_id: "pai_01J0AEPPLATFORM000000000001",
      op: "enroll",
      reason: "verified",
      service_did: "did:web:api.service.example",
      status: "active",
      verified: true
    });
  });

  it("validates pending Sign retry bounds and preserves opaque context", () => {
    expect(
      createPlatformSignPendingResponse({
        platformContext: { continuation: "opaque" },
        retryAfterSeconds: 300
      })
    ).toEqual({
      status: "pending",
      platform_context: { continuation: "opaque" },
      retry_after_seconds: "300"
    });
    expect(createPlatformSignPendingResponse({ retryAfterSeconds: 1 })).toEqual({
      status: "pending",
      retry_after_seconds: "1"
    });
    expect(() => createPlatformSignPendingResponse({ retryAfterSeconds: 0 })).toThrow(
      "integer from 1 through 300"
    );
    expect(() => createPlatformSignPendingResponse({ retryAfterSeconds: 1.5 })).toThrow(
      "integer from 1 through 300"
    );
  });

  it("rejects suspended identities for request builders", () => {
    const identity = createManagedAgentIdentity({
      agentDid: "did:web:agent.example.com:agents:123",
      status: "suspended"
    });

    expect(() =>
      createPlatformEnrollRequest({
        identity,
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      })
    ).toThrow("not active");
  });
});

function createMemoryIdentityStore(): PlatformIdentityStore {
  const identities = new Map<string, PlatformIdentityRecord>();

  return {
    create(identity) {
      identities.set(identity.agentIdentityId, cloneTestRecord(identity));
    },
    findByAgentDid(agentDid) {
      for (const identity of identities.values()) {
        if (identity.agentDid === agentDid) {
          return cloneTestRecord(identity);
        }
      }

      return undefined;
    },
    get(agentIdentityId) {
      const identity = identities.get(agentIdentityId);

      return identity === undefined ? undefined : cloneTestRecord(identity);
    },
    list() {
      return {
        identities: [...identities.values()].map(cloneTestRecord),
        total: identities.size
      };
    },
    update(agentIdentityId, update) {
      const identity = identities.get(agentIdentityId);

      if (identity === undefined) {
        return undefined;
      }

      const updated = {
        ...identity,
        ...update
      };

      identities.set(agentIdentityId, updated);
      return cloneTestRecord(updated);
    }
  };
}

function createMemoryIdempotencyStore(): PlatformIdempotencyStore {
  const records = new Map<string, PlatformIdempotencyRecord>();

  return {
    get(principal, idempotencyKey) {
      const record = records.get(`${principal}\u001f${idempotencyKey}`);

      return record === undefined ? undefined : structuredClone(record);
    },
    set(record) {
      records.set(`${record.principal}\u001f${record.idempotencyKey}`, structuredClone(record));
    }
  };
}

function createMemoryReplayStore(): PlatformReplayStore {
  const seen = new Set<string>();

  return {
    consume(key) {
      if (seen.has(key)) {
        return false;
      }

      seen.add(key);
      return true;
    }
  };
}

function cloneTestRecord(identity: PlatformIdentityRecord): PlatformIdentityRecord {
  return {
    ...identity,
    signingAlgorithms: [...identity.signingAlgorithms]
  };
}

function managedIdentityFromTestRecord(identity: PlatformIdentityRecord) {
  return createManagedAgentIdentity({
    agentDid: identity.agentDid,
    clock: () => new Date(identity.createdAt),
    status: identity.status
  });
}
