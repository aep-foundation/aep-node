import { generateKeyPairSync } from "node:crypto";

import {
  AEP_AUTHENTICATED_COMMANDS,
  AEP_VERSION,
  commandPathFromInspect,
  signClientAssertionJwt
} from "@aep-foundation/core";
import type { AepAuthenticatedCommand, AepClientAssertionClaims } from "@aep-foundation/core";
import { describe, expect, it } from "vitest";

import {
  apiKeyGrantType,
  authenticateProtectedResource,
  basicGrantType,
  buildInspectDocument,
  clientAssertionFromAepAuthorization,
  createAepService,
  createDidWebClientAssertionVerifier,
  createHostedPlatformClientAssertionVerifier,
  createInMemoryCommandIdempotencyStore,
  createInMemoryEnrollmentStore,
  createInMemoryServiceCredentialStore,
  createJwtClientAssertionVerifier,
  createStaticEnrollmentPolicy,
  didWebIdentityMethod,
  grantType,
  handleEnrollRequest,
  handleGrantRequest,
  handleRevokeRequest,
  handleStatusRequest,
  isActiveProtectedResourceAuthentication,
  oauthBearerGrantType,
  storedOAuthBearerGrantType
} from "../src/index.js";
import type {
  AepCommandIdempotencyStore,
  AepGrantTypeHandler,
  AepServiceCredentialRecord
} from "../src/index.js";

describe("@aep-foundation/service Inspect builder", () => {
  it("builds the minimal HTTP Inspect fixture shape with explicit grant and identity activation", () => {
    const document = buildInspectDocument({
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()],
      grantTypes: [oauthBearerGrantType(), apiKeyGrantType(), basicGrantType()],
      claims: {
        required: ["contact.email"]
      }
    });

    expect(document).toEqual({
      aep_version: AEP_VERSION,
      bindings: {
        supported: ["http"]
      },
      claims: {
        optional: [],
        preferred: [],
        required: ["contact.email"]
      },
      commands: {
        grant_types: ["oauth-bearer", "api-key", "basic"],
        supported: ["enroll", "grant", "inspect", "revoke", "status"]
      },
      core: {
        signing_algorithms: ["EdDSA", "ES256"]
      },
      extensions: {
        supported: []
      },
      http: {
        endpoint_base: "/aep/"
      },
      identity: {
        methods: ["did:web"]
      },
      service: {
        did: "did:web:api.example.com"
      }
    });
  });

  it("does not advertise Grant or Revoke when no grant types are enabled", () => {
    const document = buildInspectDocument({
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()]
    });

    expect(document.commands.supported).toEqual(["enroll", "inspect", "status"]);
    expect(document.commands.grant_types).toBeUndefined();
    expect(document.commands.grant_types_config).toBeUndefined();
  });

  it("advertises finalized OpenAPI location and slash matching", () => {
    const document = buildInspectDocument({
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()],
      openapi: { url: "/openapi.json", pathMatching: { trailingSlash: "equivalent" } }
    });
    expect(document.http.openapi).toEqual({
      url: "/openapi.json",
      path_matching: { trailing_slash: "equivalent" }
    });
  });

  it("advertises only explicitly enabled identity methods and grant types", () => {
    const document = buildInspectDocument({
      serviceDid: "did:web:api.example.com",
      endpointBase: "/custom-aep",
      identityMethods: [didWebIdentityMethod()],
      grantTypes: [
        grantType("custom-token", {
          issuer: "https://issuer.example.com"
        })
      ],
      signingAlgorithms: ["EdDSA", "ES256"],
      extensions: ["https://service.example/extensions/service-policy"]
    });

    expect(document.identity.methods).toEqual(["did:web"]);
    expect(document.commands.grant_types).toEqual(["custom-token"]);
    expect(document.commands.grant_types_config).toEqual({
      "custom-token": {
        issuer: "https://issuer.example.com"
      }
    });
    expect(document.core.signing_algorithms).toEqual(["EdDSA", "ES256"]);
    expect(document.extensions?.supported).toEqual([
      "https://service.example/extensions/service-policy"
    ]);
    expect(commandPathFromInspect(document, "enroll")).toBe("/custom-aep/enroll");
  });

  it("advertises targeted Revoke for stored built-in credentials", () => {
    const document = buildInspectDocument({
      grantTypes: [
        storedOAuthBearerGrantType({
          issue: () => ({
            access_token: "access-token",
            credential_id: "cred_123",
            expires_at: "2026-05-28T13:00:00Z",
            scopes: [],
            token_type: "Bearer"
          }),
          store: createInMemoryServiceCredentialStore()
        })
      ],
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:api.example.com"
    });

    expect(document.commands.grant_types_config).toEqual({
      "oauth-bearer": { supports_per_credential_revoke: "true" }
    });
  });

  it("returns defensive copies from createAepService", () => {
    const service = createAepService({
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()]
    });

    const first = service.inspectDocument();
    first.service.did = "did:web:mutated.example.com";

    expect(service.inspectDocument().service.did).toBe("did:web:api.example.com");
  });

  it("rejects missing identity methods", () => {
    expect(() =>
      buildInspectDocument({
        serviceDid: "did:web:api.example.com",
        identityMethods: []
      })
    ).toThrow("at least one identity method");
  });

  it("rejects duplicate identity methods and grant types", () => {
    expect(() =>
      buildInspectDocument({
        serviceDid: "did:web:api.example.com",
        identityMethods: [didWebIdentityMethod(), didWebIdentityMethod()]
      })
    ).toThrow("Duplicate AEP identity method");

    expect(() =>
      buildInspectDocument({
        serviceDid: "did:web:api.example.com",
        identityMethods: [didWebIdentityMethod()],
        grantTypes: [oauthBearerGrantType(), oauthBearerGrantType()]
      })
    ).toThrow("Duplicate AEP grant type");
  });
});

describe("@aep-foundation/service Enroll and Status handlers", () => {
  it("enrolls an Agent identity and returns active status", async () => {
    const store = createInMemoryEnrollmentStore();

    const enroll = await handleEnrollRequest(
      {
        agent_did: "did:web:agent.example.com:agents:123",
        claims: {
          "contact.email": "ops@example.com"
        },
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      },
      {
        clock: () => new Date("2026-05-28T12:00:00.000Z"),
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
        policy: createStaticEnrollmentPolicy(),
        store
      }
    );

    expect(enroll).toEqual({
      body: {
        status: "active"
      },
      contentType: "application/aep+json",
      status: 200
    });

    await expect(
      handleStatusRequest("did:web:agent.example.com:agents:123", { store })
    ).resolves.toEqual({
      body: {
        since: "2026-05-28T12:00:00.000Z",
        status: "active"
      },
      contentType: "application/aep+json",
      status: 200
    });
  });

  it("enforces configurable Claim Value resource limits before policy and storage", async () => {
    const baseRequest = {
      agent_did: "did:web:agent.example.com:agents:123",
      idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
    };
    const cases = [
      {
        claims: { "example.value": "12345" },
        limits: { maxStringLength: 4 }
      },
      {
        claims: { first: true, second: true },
        limits: { maxMemberCount: 1 }
      },
      {
        claims: { nested: { too: { deep: { object: true } } } },
        limits: { maxObjectDepth: 3 }
      },
      {
        claims: { "example.value": "encoded payload" },
        limits: { maxEncodedBytes: 8 }
      }
    ] as const;

    for (const testCase of cases) {
      let policyCalled = false;
      const response = await handleEnrollRequest(
        {
          ...baseRequest,
          claims: testCase.claims
        },
        {
          claimValueLimits: testCase.limits,
          idempotencyKey: baseRequest.idempotency_key,
          policy: {
            decideEnrollment: () => {
              policyCalled = true;
              return {};
            }
          },
          store: createInMemoryEnrollmentStore()
        }
      );

      expect(response, JSON.stringify(testCase.limits)).toMatchObject({
        body: {
          code: "invalid_request"
        },
        status: 400
      });
      expect(policyCalled).toBe(false);
    }
  });

  it("rejects invalid Claim Value limit configuration", () => {
    expect(() =>
      createAepService({
        claims: {
          limits: {
            maxObjectDepth: 0
          }
        },
        identityMethods: [didWebIdentityMethod()],
        serviceDid: "did:web:api.example.com"
      })
    ).toThrow("maxObjectDepth must be a positive safe integer");
  });

  it("supports pending enrollment requirements", async () => {
    const store = createInMemoryEnrollmentStore();

    await expect(
      handleEnrollRequest(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        },
        {
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
          policy: createStaticEnrollmentPolicy({
            ownerActionRequired: true,
            requirementsPending: ["owner-approval"],
            verificationPending: ["contact.email"],
            status: "pending"
          }),
          store
        }
      )
    ).resolves.toEqual({
      body: {
        owner_action_required: "true",
        requirements_pending: ["owner-approval"],
        verification_pending: ["contact.email"],
        status: "pending"
      },
      contentType: "application/aep+json",
      status: 200
    });
  });

  it("replays matching Enroll idempotency keys", async () => {
    const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
    const store = createInMemoryEnrollmentStore();
    const request = {
      agent_did: "did:web:agent.example.com:agents:123",
      idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
    };
    const options = {
      commandIdempotencyStore,
      idempotencyKey: request.idempotency_key,
      policy: createStaticEnrollmentPolicy(),
      store
    };

    const first = await handleEnrollRequest(request, options);
    const second = await handleEnrollRequest({ ...request }, options);

    expect(second).toEqual(first);
  });

  it("accepts an Enroll header key without the optional body copy", async () => {
    await expect(
      handleEnrollRequest(
        {
          agent_did: "did:web:agent.example.com:agents:123"
        },
        {
          idempotencyKey: "header-only-enroll",
          policy: createStaticEnrollmentPolicy(),
          store: createInMemoryEnrollmentStore()
        }
      )
    ).resolves.toMatchObject({
      body: { status: "active" },
      status: 200
    });
  });

  it("rejects empty Core command idempotency keys before executing handlers", async () => {
    const store = createInMemoryEnrollmentStore([
      activeEnrollment("did:web:agent.example.com:agents:123")
    ]);
    const handler = createGrantHandler();
    const responses = await Promise.all([
      handleEnrollRequest(
        { agent_did: "did:web:agent.example.com:agents:123" },
        {
          idempotencyKey: "",
          policy: createStaticEnrollmentPolicy(),
          store
        }
      ),
      handleGrantRequest(
        { grant_type: "oauth-bearer" },
        {
          agentDid: "did:web:agent.example.com:agents:123",
          handlers: new Map([["oauth-bearer", handler]]),
          idempotencyKey: "",
          store
        }
      ),
      handleRevokeRequest(
        { grant_type: "oauth-bearer" },
        {
          agentDid: "did:web:agent.example.com:agents:123",
          handlers: new Map([["oauth-bearer", handler]]),
          idempotencyKey: " ",
          store
        }
      )
    ]);

    expect(responses).toEqual(
      responses.map(() => ({
        body: {
          code: "invalid_request",
          status: 400,
          title: "Invalid request",
          type: "urn:aep:error:invalid_request"
        },
        contentType: "application/problem+json",
        status: 400
      }))
    );
    expect(handler.events).toEqual([]);
  });

  it("conflicts when one Agent reuses an idempotency key across commands", async () => {
    const store = createInMemoryCommandIdempotencyStore();
    const first = {
      agentDid: "did:web:agent.example.com:agents:123",
      command: "grant" as const,
      idempotencyKey: "cross-command-key",
      requestHash: "sha256:request"
    };

    await store.executeIdempotentCommand(first, () => ({
      body: { credential_id: "cred_123" },
      contentType: "application/aep+json",
      status: 200
    }));

    await expect(
      store.executeIdempotentCommand(
        {
          ...first,
          command: "revoke"
        },
        () => ({ body: {}, contentType: "application/aep+json", status: 200 })
      )
    ).resolves.toEqual({ state: "conflict" });

    await expect(
      store.executeIdempotentCommand(
        {
          ...first,
          agentDid: "did:web:agent.example.com:agents:456"
        },
        () => ({ body: {}, contentType: "application/aep+json", status: 200 })
      )
    ).resolves.toMatchObject({ state: "created" });
  });

  it("uses a canonical SHA-256 request fingerprint", async () => {
    let requestHash: string | undefined;
    const commandIdempotencyStore: AepCommandIdempotencyStore = {
      async executeIdempotentCommand(input, execute) {
        requestHash = input.requestHash;
        return { response: await execute(), state: "created" };
      }
    };

    await handleEnrollRequest(
      {
        agent_did: "did:web:agent.example.com:agents:123",
        claims: {
          "contact.email": "ops@example.com"
        }
      },
      {
        commandIdempotencyStore,
        idempotencyKey: "hashed-request",
        policy: createStaticEnrollmentPolicy(),
        store: createInMemoryEnrollmentStore()
      }
    );

    expect(requestHash).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });

  it("returns an existing enrollment without reevaluating policy or replacing it", async () => {
    const existing = activeEnrollment("did:web:agent.example.com:agents:123");
    const store = createInMemoryEnrollmentStore([existing]);
    const storedBefore = await store.findEnrollment(existing.agentDid);
    let policyCalls = 0;

    const response = await handleEnrollRequest(
      {
        agent_did: existing.agentDid,
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-111111111111"
      },
      {
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-111111111111",
        policy: {
          decideEnrollment: () => {
            policyCalls += 1;
            return { status: "rejected" };
          }
        },
        store
      }
    );

    expect(response).toEqual({
      body: { status: "active" },
      contentType: "application/aep+json",
      status: 200
    });
    expect(policyCalls).toBe(0);
    expect(await store.findEnrollment(existing.agentDid)).toEqual(storedBefore);
  });

  it("serializes concurrent matching command idempotency keys", async () => {
    const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
    const started = deferred<void>();
    const release = deferred<void>();
    let executions = 0;
    const input = {
      agentDid: "did:web:agent.example.com:agents:123",
      command: "enroll" as const,
      idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
      requestHash: "matching-request"
    };

    const first = commandIdempotencyStore.executeIdempotentCommand(input, async () => {
      executions += 1;
      started.resolve(undefined);
      await release.promise;

      return {
        body: {
          status: "active"
        },
        contentType: "application/aep+json",
        status: 200
      };
    });

    await started.promise;

    const second = commandIdempotencyStore.executeIdempotentCommand(input, () => {
      executions += 1;

      return {
        body: {
          status: "active"
        },
        contentType: "application/aep+json",
        status: 200
      };
    });

    release.resolve(undefined);

    const results = await Promise.all([first, second]);

    expect(results[0]).toEqual({
      response: {
        body: {
          status: "active"
        },
        contentType: "application/aep+json",
        status: 200
      },
      state: "created"
    });
    expect(results[1].state).toBe("replayed");

    if (results[1].state !== "replayed") {
      throw new Error(`Expected replayed idempotency result, got ${results[1].state}.`);
    }

    expect(results[1].record).toMatchObject({
      body: {
        status: "active"
      },
      contentType: "application/aep+json",
      status: 200
    });
    expect(results[1].record).toMatchObject({
      agentDid: input.agentDid,
      command: input.command,
      idempotencyKey: input.idempotencyKey,
      requestHash: input.requestHash
    });
    expect(executions).toBe(1);
  });

  it("rejects conflicting Enroll idempotency keys", async () => {
    const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
    const store = createInMemoryEnrollmentStore();
    const options = {
      commandIdempotencyStore,
      idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
      policy: createStaticEnrollmentPolicy(),
      store
    };

    await handleEnrollRequest(
      {
        agent_did: "did:web:agent.example.com:agents:123",
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      },
      options
    );

    await expect(
      handleEnrollRequest(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          claims: {
            "contact.email": "different@example.com"
          },
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        },
        options
      )
    ).resolves.toEqual({
      body: {
        code: "idempotency_conflict",
        status: 409,
        title: "Idempotency conflict",
        type: "urn:aep:error:idempotency_conflict"
      },
      contentType: "application/problem+json",
      status: 409
    });
  });

  it("returns Problem Details for invalid Enroll and unknown Status requests", async () => {
    const store = createInMemoryEnrollmentStore();

    await expect(
      handleEnrollRequest(
        {},
        {
          idempotencyKey: "invalid-enroll",
          policy: createStaticEnrollmentPolicy(),
          store
        }
      )
    ).resolves.toEqual({
      body: {
        code: "invalid_request",
        status: 400,
        title: "Invalid request",
        type: "urn:aep:error:invalid_request"
      },
      contentType: "application/problem+json",
      status: 400
    });

    await expect(handleStatusRequest("did:web:missing.example.com", { store })).resolves.toEqual({
      body: {
        code: "not_recognized",
        status: 401,
        title: "Not recognized",
        type: "urn:aep:error:not_recognized"
      },
      contentType: "application/problem+json",
      headers: { "WWW-Authenticate": 'AEP reason="not_recognized"' },
      status: 401
    });
  });

  it("exposes Enroll and Status through createAepService", async () => {
    const verificationIdempotencyKeys: Array<string | undefined> = [];
    const service = createAepService({
      clock: () => new Date("2026-05-28T12:00:00.000Z"),
      clientAssertion: assertionConfig(),
      clientAssertionVerifier: (assertion, context) => {
        verificationIdempotencyKeys.push(context.idempotencyKey);
        return parseJsonAssertion(assertion);
      },
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()]
    });

    await expect(
      service.enroll(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        },
        {
          clientAssertion: clientAssertion("enroll", "enroll-create"),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        }
      )
    ).resolves.toMatchObject({
      body: {
        status: "active"
      },
      status: 200
    });

    await expect(
      service.status({
        clientAssertion: clientAssertion("status", "status-create"),
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-status000000"
      })
    ).resolves.toMatchObject({
      body: {
        since: "2026-05-28T12:00:00.000Z",
        status: "active"
      },
      status: 200
    });
    expect(verificationIdempotencyKeys).toEqual([
      "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
      "9f8a4d2e-1c3b-4f5e-8b7a-status000000"
    ]);
  });

  it("rejects new enrollment when an advertised required Claim is missing", async () => {
    const service = createAepService({
      claims: {
        required: ["contact.email"]
      },
      clientAssertion: assertionConfig(),
      clientAssertionVerifier: parseJsonAssertion,
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()]
    });

    await expect(
      service.enroll(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-required00000"
        },
        {
          clientAssertion: clientAssertion("enroll", "missing-required-claim"),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-required00000"
        }
      )
    ).resolves.toEqual({
      body: {
        code: "requirements_unmet",
        requirements_pending: ["contact.email"],
        status: 422,
        title: "Requirements unmet",
        type: "urn:aep:error:requirements_unmet"
      },
      contentType: "application/problem+json",
      status: 422
    });
  });

  it("verifies baseline client assertion claims at the public command boundary", async () => {
    const service = createAepService({
      clientAssertion: assertionConfig(),
      clientAssertionVerifier: parseJsonAssertion,
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()]
    });

    await expect(
      service.enroll(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        },
        {
          clientAssertion: clientAssertion("status", "wrong-op"),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        }
      )
    ).resolves.toMatchObject({
      body: {
        code: "not_recognized"
      },
      status: 401
    });

    await expect(
      service.enroll(
        {
          agent_did: "did:web:different.example.com",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        },
        {
          clientAssertion: clientAssertion("enroll", "wrong-agent"),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        }
      )
    ).resolves.toMatchObject({
      body: {
        code: "not_recognized"
      },
      status: 401
    });

    const replayedAssertion = clientAssertion("enroll", "replayed");

    await expect(
      service.enroll(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000001"
        },
        {
          clientAssertion: replayedAssertion,
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000001"
        }
      )
    ).resolves.toMatchObject({
      status: 200
    });

    await expect(
      service.enroll(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000002"
        },
        {
          clientAssertion: replayedAssertion,
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000002"
        }
      )
    ).resolves.toMatchObject({
      body: {
        code: "not_recognized"
      },
      status: 401
    });
  });

  it("verifies signed JWT client assertions at the public command boundary", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256"
    });
    const service = createAepService({
      clientAssertion: assertionConfig(),
      clientAssertionVerifier: createJwtClientAssertionVerifier({
        algorithms: ["ES256"],
        currentDate: new Date("2026-05-28T12:00:00.000Z"),
        key: publicKey
      }),
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:api.example.com"
    });

    await expect(
      service.enroll(
        {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        },
        {
          clientAssertion: await signClientAssertionJwt(
            clientAssertionClaims("enroll", "jwt-enroll"),
            {
              alg: "ES256",
              key: privateKey
            }
          ),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
        }
      )
    ).resolves.toMatchObject({
      body: {
        status: "active"
      },
      status: 200
    });
  });
});

describe("@aep-foundation/service protected resource authentication helpers", () => {
  it("authenticates resource-bound AEP JWT assertions and rejects unsupported JWT presentation", async () => {
    const resource = "https://api.example.com/orders/123";
    const claims = {
      ...clientAssertionClaims("status", "authenticate-resource"),
      op: "authenticate" as const,
      resource
    };
    const service = createAepService({
      authenticationMethods: ["aep-jwt"],
      clientAssertion: assertionConfig(),
      clientAssertionVerifier: parseJsonAssertion,
      identityMethods: [didWebIdentityMethod()],
      inspectUrl: "https://api.example.com/.well-known/aep",
      serviceDid: "did:web:api.example.com"
    });
    await expect(
      service.authenticateProtectedResource({
        headers: new Headers({ Authorization: `AEP ${JSON.stringify(claims)}` }),
        method: "GET",
        url: resource
      })
    ).resolves.toMatchObject({
      authenticated: true,
      principal: { authenticationMethod: "aep-jwt" }
    });

    const unsupported = createAepService({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:api.example.com"
    });
    await expect(
      unsupported.authenticateProtectedResource({
        headers: { Authorization: "AEP assertion" },
        method: "GET",
        url: resource
      })
    ).resolves.toMatchObject({
      authenticated: false,
      response: { body: { code: "unsupported_authentication_method" } }
    });
  });

  it("selects the dedicated carrier, composes unrelated Authorization, and fails closed on ambiguity", async () => {
    const service = createAepService({
      authenticationMethods: ["custom-session"],
      grantTypes: [
        grantType("custom-session", undefined, {
          authenticate: ({ headers }) =>
            headers["authorization"] === "Bearer valid"
              ? {
                  agentDid: "did:web:agent.example",
                  authenticationKind: "session-credential",
                  authenticationMethod: "custom-session",
                  grantType: "custom-session"
                }
              : undefined,
          grant: () => ({}),
          revoke: () => undefined
        })
      ],
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:api.example.com"
    });
    await expect(
      service.authenticateProtectedResource({
        headers: { "AEP-Authorization": "Bearer valid", Authorization: "Payment orthogonal" },
        method: "GET",
        url: "https://api.example.com/orders"
      })
    ).resolves.toMatchObject({ authenticated: true });
    await expect(
      service.authenticateProtectedResource({
        headers: { "AEP-Authorization": "Bearer valid", Authorization: "Basic other" },
        method: "GET",
        url: "https://api.example.com/orders"
      })
    ).resolves.toMatchObject({
      authenticated: false,
      response: { body: { code: "not_recognized" } }
    });
    await expect(
      service.authenticateProtectedResource({
        headers: { "AEP-Authorization": ["Bearer valid", "Bearer other"] },
        method: "GET",
        url: "https://api.example.com/orders"
      })
    ).resolves.toMatchObject({
      authenticated: false,
      response: { body: { code: "not_recognized" } }
    });
  });

  it("authenticates through registered handlers and otherwise emits the finalized challenge", async () => {
    const service = createAepService({
      authenticationMethods: ["custom-session"],
      grantTypes: [
        grantType("custom-session", undefined, {
          authenticate: ({ headers }) =>
            headers["x-session"] === "valid"
              ? {
                  agentDid: "did:web:agent.example",
                  authenticationKind: "session-credential",
                  authenticationMethod: "custom-session",
                  credentialId: "credential-1",
                  grantType: "custom-session",
                  scopes: ["read"]
                }
              : undefined,
          grant: () => ({}),
          revoke: () => undefined
        })
      ],
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:api.example.com"
    });
    await expect(
      service.authenticateProtectedResource({
        headers: { "X-Session": "valid" },
        method: "GET",
        url: "https://api.example.com/orders"
      })
    ).resolves.toMatchObject({
      authenticated: true,
      principal: { agentDid: "did:web:agent.example", scopes: ["read"] }
    });
    const missing = await service.authenticateProtectedResource({
      headers: {},
      method: "GET",
      url: "https://api.example.com/orders"
    });
    expect(missing).toMatchObject({ authenticated: false, response: { status: 401 } });
    if (!missing.authenticated)
      expect(missing.response.headers?.["WWW-Authenticate"]).toContain(
        'service_did="did:web:api.example.com"'
      );
  });

  it("delegates protected resource authentication to the unified Service API", async () => {
    const result = await authenticateProtectedResource(
      {
        authenticateProtectedResource: () =>
          Promise.resolve({
            authenticated: true,
            principal: {
              agentDid: "did:web:agent.example",
              authenticationKind: "aep-jwt",
              authenticationMethod: "aep-jwt"
            }
          })
      },
      {
        headers: { Authorization: "AEP jwt.authenticate" },
        method: "GET",
        url: "https://service.example/resource"
      }
    );

    expect(clientAssertionFromAepAuthorization("AEP jwt.status")).toBe("jwt.status");
    expect(clientAssertionFromAepAuthorization("Bearer token")).toBe("");
    expect(isActiveProtectedResourceAuthentication(result)).toBe(true);
  });

  it("creates a did:web client assertion verifier", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256"
    });
    const publicKeyJwk = publicKey.export({
      format: "jwk"
    });
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signClientAssertionJwt(
      {
        aud: "did:web:api.example.com",
        exp: now + 300,
        iat: now,
        iss: "did:web:agent.example.com:agents:123",
        jti: "did-web-verifier-test",
        op: "status",
        sub: "did:web:agent.example.com:agents:123"
      },
      {
        alg: "ES256",
        key: privateKey,
        kid: "did:web:agent.example.com:agents:123#key-1"
      }
    );
    const verifier = createDidWebClientAssertionVerifier({
      fetch: () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              verificationMethod: [
                {
                  id: "did:web:agent.example.com:agents:123#key-1",
                  publicKeyJwk
                }
              ]
            })
          )
        )
    });

    await expect(
      verifier(jwt, {
        clientAssertion: jwt,
        command: "status",
        serviceDid: "did:web:api.example.com",
        signingAlgorithms: ["ES256"]
      })
    ).resolves.toMatchObject({
      jti: "did-web-verifier-test",
      sub: "did:web:agent.example.com:agents:123"
    });
  });

  it("creates a hosted Platform client assertion verifier", async () => {
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256"
    });
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signClientAssertionJwt(
      {
        aud: "did:web:api.example.com",
        exp: now + 300,
        iat: now,
        iss: "did:web:platform.example.com:agents:4Yf7p2xQd9",
        jti: "hosted-verifier-test",
        op: "status",
        sub: "did:web:platform.example.com:agents:4Yf7p2xQd9"
      },
      {
        alg: "ES256",
        key: privateKey,
        kid: "did:web:platform.example.com:agents:4Yf7p2xQd9"
      }
    );
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const verifier = createHostedPlatformClientAssertionVerifier({
      authorization: "Bearer service-demo",
      endpoint: "https://platform.example.com/v1/aep/verifications",
      fetch(input, init) {
        calls.push({
          input,
          ...(init === undefined ? {} : { init })
        });
        return Promise.resolve(
          new Response(
            JSON.stringify({
              agent_did: "did:web:platform.example.com:agents:4Yf7p2xQd9",
              agent_identity_id: "pai_01J0AEPPLATFORM000000000001",
              op: "status",
              reason: "verified",
              service_did: "did:web:api.example.com",
              status: "active",
              verified: true
            })
          )
        );
      }
    });

    await expect(
      verifier(jwt, {
        clientAssertion: jwt,
        command: "status",
        serviceDid: "did:web:api.example.com",
        signingAlgorithms: ["ES256"]
      })
    ).resolves.toMatchObject({
      jti: "hosted-verifier-test",
      sub: "did:web:platform.example.com:agents:4Yf7p2xQd9"
    });
    await verifier(jwt, {
      clientAssertion: jwt,
      command: "status",
      idempotencyKey: "hosted-verification-request",
      serviceDid: "did:web:api.example.com",
      signingAlgorithms: ["ES256"]
    });
    expect(String(calls[0]?.input)).toBe("https://platform.example.com/v1/aep/verifications");
    expect(calls[0]?.init?.headers).toEqual({
      Accept: "application/aep+json",
      Authorization: "Bearer service-demo",
      "Content-Type": "application/aep+json",
      "Idempotency-Key": "hosted-verifier-test"
    });
    expect(calls[1]?.init?.headers).toMatchObject({
      "Idempotency-Key": "hosted-verification-request"
    });
    const body = calls[0]?.init?.body;

    if (typeof body !== "string") {
      throw new Error("Expected hosted verification request body to be a string.");
    }

    expect(JSON.parse(body)).toEqual({
      client_assertion: jwt,
      op: "status",
      service_did: "did:web:api.example.com"
    });
  });
});

describe("@aep-foundation/service Grant and Revoke handlers", () => {
  it("dispatches Grant requests to the selected grant type handler", async () => {
    const store = createInMemoryEnrollmentStore([
      activeEnrollment("did:web:agent.example.com:agents:123")
    ]);
    const handler = createGrantHandler();

    await expect(
      handleGrantRequest(
        {
          grant_type: "oauth-bearer",
          requested_scopes: ["read"]
        },
        {
          agentDid: "did:web:agent.example.com:agents:123",
          handlers: new Map([["oauth-bearer", handler]]),
          idempotencyKey: "grant-dispatch",
          store
        }
      )
    ).resolves.toEqual({
      body: {
        access_token: "access-token",
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        scopes: ["read"],
        token_type: "Bearer"
      },
      contentType: "application/aep+json",
      status: 200
    });

    expect(handler.events).toEqual([
      {
        agentDid: "did:web:agent.example.com:agents:123",
        grantType: "oauth-bearer",
        op: "grant",
        request: {
          grant_type: "oauth-bearer",
          requested_scopes: ["read"]
        }
      }
    ]);
  });

  it("replays matching Grant idempotency keys and rejects conflicting reuse", async () => {
    const store = createInMemoryEnrollmentStore([
      activeEnrollment("did:web:agent.example.com:agents:123")
    ]);
    const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
    const handler = createGrantHandler();
    const request = {
      grant_type: "oauth-bearer",
      requested_scopes: ["read"]
    };
    const options = {
      agentDid: "did:web:agent.example.com:agents:123",
      handlers: new Map([["oauth-bearer", handler]]),
      idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-grant0000000",
      commandIdempotencyStore,
      store
    };

    const first = await handleGrantRequest(request, options);
    const second = await handleGrantRequest({ ...request }, options);

    expect(second).toEqual(first);
    expect(handler.events).toHaveLength(1);

    await expect(
      handleGrantRequest(
        {
          grant_type: "oauth-bearer",
          requested_scopes: ["write"]
        },
        options
      )
    ).resolves.toMatchObject({
      body: {
        code: "idempotency_conflict"
      },
      contentType: "application/problem+json",
      status: 409
    });
  });

  it("rejects Grant requests for unsupported grant types", async () => {
    const store = createInMemoryEnrollmentStore([
      activeEnrollment("did:web:agent.example.com:agents:123")
    ]);

    await expect(
      handleGrantRequest(
        {
          grant_type: "oauth-bearer"
        },
        {
          agentDid: "did:web:agent.example.com:agents:123",
          handlers: new Map(),
          idempotencyKey: "unsupported-grant",
          store
        }
      )
    ).resolves.toEqual({
      body: {
        code: "unsupported_grant_type",
        status: 400,
        title: "Unsupported grant type",
        type: "urn:aep:error:unsupported_grant_type"
      },
      contentType: "application/problem+json",
      status: 400
    });
  });

  it("requires active enrollment for Grant requests", async () => {
    const store = createInMemoryEnrollmentStore([
      {
        ...activeEnrollment("did:web:agent.example.com:agents:123"),
        ownerActionRequired: true,
        requirementsPending: ["contact.address.primary"],
        verificationPending: ["contact.email"],
        status: "pending"
      }
    ]);

    await expect(
      handleGrantRequest(
        {
          grant_type: "oauth-bearer"
        },
        {
          agentDid: "did:web:agent.example.com:agents:123",
          handlers: new Map([["oauth-bearer", createGrantHandler()]]),
          idempotencyKey: "pending-grant",
          store
        }
      )
    ).resolves.toEqual({
      body: {
        code: "verification_pending",
        owner_action_required: "true",
        requirements_pending: ["contact.address.primary"],
        status: 403,
        title: "Verification pending",
        type: "urn:aep:error:verification_pending",
        verification_pending: ["contact.email"]
      },
      contentType: "application/problem+json",
      status: 403
    });
  });

  it("dispatches Revoke requests by grant type", async () => {
    const store = createInMemoryEnrollmentStore([
      activeEnrollment("did:web:agent.example.com:agents:123")
    ]);
    const handler = createGrantHandler();

    await expect(
      handleRevokeRequest(
        {
          grant_type: "oauth-bearer"
        },
        {
          agentDid: "did:web:agent.example.com:agents:123",
          handlers: new Map([["oauth-bearer", handler]]),
          idempotencyKey: "revoke-dispatch",
          store
        }
      )
    ).resolves.toEqual({
      body: {},
      contentType: "application/aep+json",
      status: 200
    });

    expect(handler.events).toEqual([
      {
        agentDid: "did:web:agent.example.com:agents:123",
        grantType: "oauth-bearer",
        op: "revoke",
        request: {
          grant_type: "oauth-bearer"
        }
      }
    ]);
  });

  it("replays matching Revoke idempotency keys and rejects conflicting reuse", async () => {
    const store = createInMemoryEnrollmentStore([
      activeEnrollment("did:web:agent.example.com:agents:123")
    ]);
    const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
    const handler = createGrantHandler();
    const request = {
      grant_type: "oauth-bearer"
    };
    const options = {
      agentDid: "did:web:agent.example.com:agents:123",
      handlers: new Map([["oauth-bearer", handler]]),
      idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-revoke000000",
      commandIdempotencyStore,
      store
    };

    const first = await handleRevokeRequest(request, options);
    const second = await handleRevokeRequest({ ...request }, options);

    expect(second).toEqual(first);
    expect(handler.events).toHaveLength(1);

    await expect(
      handleRevokeRequest(
        {
          credential_id: "cred_123",
          grant_type: "oauth-bearer"
        },
        options
      )
    ).resolves.toMatchObject({
      body: {
        code: "idempotency_conflict"
      },
      contentType: "application/problem+json",
      status: 409
    });
  });

  it("fans out all-grant-types Revoke and targets credentials by grant type", async () => {
    const store = createInMemoryEnrollmentStore([
      activeEnrollment("did:web:agent.example.com:agents:123")
    ]);
    const oauth = createGrantHandler();
    const apiKey = createGrantHandler();
    const handlers = new Map([
      ["oauth-bearer", oauth],
      ["api-key", apiKey]
    ]);

    await handleRevokeRequest(
      {
        all_grant_types: "true"
      },
      {
        agentDid: "did:web:agent.example.com:agents:123",
        handlers,
        idempotencyKey: "revoke-all",
        store
      }
    );
    await handleRevokeRequest(
      {
        credential_id: "cred_123",
        grant_type: "oauth-bearer"
      },
      {
        agentDid: "did:web:agent.example.com:agents:123",
        handlers,
        idempotencyKey: "revoke-credential",
        store
      }
    );

    expect([...oauth.events, ...apiKey.events]).toEqual([
      {
        agentDid: "did:web:agent.example.com:agents:123",
        grantType: "oauth-bearer",
        op: "revoke",
        request: {
          all_grant_types: "true"
        }
      },
      {
        agentDid: "did:web:agent.example.com:agents:123",
        grantType: "oauth-bearer",
        op: "revoke",
        request: {
          credential_id: "cred_123",
          grant_type: "oauth-bearer"
        }
      },
      {
        agentDid: "did:web:agent.example.com:agents:123",
        grantType: "api-key",
        op: "revoke",
        request: {
          all_grant_types: "true"
        }
      }
    ]);
  });

  it("returns Problem Details for invalid Revoke and unknown Agent requests", async () => {
    const store = createInMemoryEnrollmentStore();

    await expect(
      handleRevokeRequest(
        {
          all_grant_types: "true",
          grant_type: "oauth-bearer"
        },
        {
          agentDid: "did:web:agent.example.com:agents:123",
          handlers: new Map([["oauth-bearer", createGrantHandler()]]),
          idempotencyKey: "invalid-revoke",
          store
        }
      )
    ).resolves.toMatchObject({
      body: {
        code: "invalid_request"
      },
      contentType: "application/problem+json",
      status: 400
    });

    await expect(
      handleGrantRequest(
        {
          grant_type: "oauth-bearer"
        },
        {
          agentDid: "did:web:missing.example.com",
          handlers: new Map([["oauth-bearer", createGrantHandler()]]),
          idempotencyKey: "unknown-agent-grant",
          store
        }
      )
    ).resolves.toMatchObject({
      body: {
        code: "not_recognized"
      },
      contentType: "application/problem+json",
      status: 401
    });
  });

  it("exposes Grant and Revoke through createAepService", async () => {
    const handler = createGrantHandler();
    const service = createAepService({
      clientAssertion: assertionConfig(),
      clientAssertionVerifier: parseJsonAssertion,
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()],
      grantTypes: [grantType("oauth-bearer", undefined, handler)]
    });

    await service.enroll(
      {
        agent_did: "did:web:agent.example.com:agents:123",
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      },
      {
        clientAssertion: clientAssertion("enroll", "enroll-grant-revoke"),
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      }
    );

    await expect(
      service.grant(
        {
          grant_type: "oauth-bearer"
        },
        {
          clientAssertion: clientAssertion("grant", "grant-create"),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-grant0000000"
        }
      )
    ).resolves.toMatchObject({
      body: {
        credential_id: "cred_123"
      },
      status: 200
    });

    await expect(
      service.revoke(
        {
          grant_type: "oauth-bearer"
        },
        {
          clientAssertion: clientAssertion("revoke", "revoke-create"),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-revoke000000"
        }
      )
    ).resolves.toEqual({
      body: {},
      contentType: "application/aep+json",
      status: 200
    });
  });

  it("persists and revokes built-in issued credentials", async () => {
    const credentialStore = createInMemoryServiceCredentialStore();
    const service = createAepService({
      authenticationMethods: ["oauth-bearer"],
      clientAssertion: assertionConfig(),
      clientAssertionVerifier: parseJsonAssertion,
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()],
      grantTypes: [
        storedOAuthBearerGrantType({
          clock: () => new Date("2026-05-28T12:00:00.000Z"),
          issue: (request) => ({
            access_token: "access-token",
            credential_id: "cred_123",
            expires_at: "2026-05-28T13:00:00Z",
            scopes: request.requested_scopes ?? [],
            token_type: "Bearer"
          }),
          store: credentialStore
        })
      ]
    });

    await service.enroll(
      {
        agent_did: "did:web:agent.example.com:agents:123",
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      },
      {
        clientAssertion: clientAssertion("enroll", "enroll-stored-credential"),
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      }
    );

    await expect(
      service.grant(
        {
          grant_type: "oauth-bearer",
          requested_scopes: ["read"]
        },
        {
          clientAssertion: clientAssertion("grant", "grant-stored-credential"),
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-agentgrant"
        }
      )
    ).resolves.toMatchObject({
      body: {
        credential_id: "cred_123",
        scopes: ["read"],
        token_type: "Bearer"
      },
      status: 200
    });

    expect(
      await credentialStore.findCredential(
        "did:web:agent.example.com:agents:123",
        "oauth-bearer",
        "cred_123"
      )
    ).toMatchObject({
      agentDid: "did:web:agent.example.com:agents:123",
      createdAt: "2026-05-28T12:00:00.000Z",
      credentialId: "cred_123",
      expiresAt: "2026-05-28T13:00:00Z",
      grantType: "oauth-bearer"
    });

    await expect(
      service.authenticateProtectedResource({
        headers: { Authorization: "Bearer access-token" },
        method: "GET",
        url: "https://api.example.com/resource"
      })
    ).resolves.toMatchObject({
      authenticated: true,
      principal: { credentialId: "cred_123", scopes: ["read"] }
    });

    await service.revoke(
      {
        credential_id: "cred_123",
        grant_type: "oauth-bearer"
      },
      {
        clientAssertion: clientAssertion("revoke", "revoke-stored-credential"),
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-agentrevoke"
      }
    );

    expect(
      await credentialStore.findCredential(
        "did:web:agent.example.com:agents:123",
        "oauth-bearer",
        "cred_123"
      )
    ).toMatchObject({
      revokedAt: "2026-05-28T12:00:00.000Z"
    });
    await expect(
      service.authenticateProtectedResource({
        headers: { Authorization: "Bearer access-token" },
        method: "GET",
        url: "https://api.example.com/resource"
      })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("rejects reuse of a Service-issued credential identifier", async () => {
    const credentialStore = createInMemoryServiceCredentialStore();
    const first = serviceCredentialRecord("did:web:agent.example.com:agents:one", "oauth-bearer");
    const second = serviceCredentialRecord("did:web:agent.example.com:agents:two", "api-key");

    await credentialStore.saveCredential(first);
    expect(() => credentialStore.saveCredential(second)).toThrow(
      "AEP credential identifier is already issued: shared-credential-id."
    );
  });
});

function assertionConfig() {
  return {
    clock: () => new Date("2026-05-28T12:00:00.000Z")
  };
}

function clientAssertion(command: AepAuthenticatedCommand, jti: string): string {
  return JSON.stringify(clientAssertionClaims(command, jti));
}

function clientAssertionClaims(
  command: AepAuthenticatedCommand,
  jti: string
): AepClientAssertionClaims {
  if (!AEP_AUTHENTICATED_COMMANDS.includes(command)) {
    throw new TypeError(`Unsupported authenticated command: ${command}.`);
  }

  return {
    aud: "did:web:api.example.com",
    exp: 1779969900,
    iat: 1779969600,
    iss: "did:web:agent.example.com:agents:123",
    jti,
    op: command,
    sub: "did:web:agent.example.com:agents:123"
  };
}

function parseJsonAssertion(assertion: string): AepClientAssertionClaims {
  return JSON.parse(assertion) as AepClientAssertionClaims;
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolvePromise: (value: T) => void = () => {
    throw new Error("Deferred promise was resolved before initialization.");
  };
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });

  return {
    promise,
    resolve: resolvePromise
  };
}

function activeEnrollment(agentDid: string) {
  return {
    agentDid,
    claims: {},
    createdAt: "2026-05-28T12:00:00.000Z",
    ownerActionRequired: false,
    requirementsPending: [],
    since: "2026-05-28T12:00:00.000Z",
    status: "active" as const,
    updatedAt: "2026-05-28T12:00:00.000Z"
  };
}

function serviceCredentialRecord(
  agentDid: string,
  grantType: "api-key" | "oauth-bearer"
): AepServiceCredentialRecord {
  const credentialId = "shared-credential-id";
  const expiresAt = "2999-05-28T12:00:00Z";
  return {
    agentDid,
    createdAt: "2026-05-28T12:00:00Z",
    credential:
      grantType === "api-key"
        ? {
            api_key: "api-key",
            credential_id: credentialId,
            expires_at: expiresAt,
            header: "X-API-Key",
            scopes: []
          }
        : {
            access_token: "access-token",
            credential_id: credentialId,
            expires_at: expiresAt,
            scopes: [],
            token_type: "Bearer"
          },
    credentialId,
    expiresAt,
    grantType
  };
}

function createGrantHandler(): AepGrantTypeHandler & {
  events: Array<{
    agentDid: string;
    grantType: string;
    op: "grant" | "revoke";
    request: unknown;
  }>;
} {
  const events: Array<{
    agentDid: string;
    grantType: string;
    op: "grant" | "revoke";
    request: unknown;
  }> = [];

  return {
    events,
    grant(request, context) {
      events.push({
        agentDid: context.agentDid,
        grantType: context.grantType,
        op: "grant",
        request
      });

      return {
        access_token: "access-token",
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        scopes: request.requested_scopes ?? [],
        token_type: "Bearer"
      };
    },
    revoke(request, context) {
      events.push({
        agentDid: context.agentDid,
        grantType: context.grantType,
        op: "revoke",
        request
      });
    }
  };
}
