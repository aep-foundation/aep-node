import { generateKeyPairSync } from "node:crypto";

import { AEP_MEDIA_TYPE, verifyClientAssertionJwt } from "@aep-foundation/core";
import type { InspectDocument } from "@aep-foundation/core";
import { describe, expect, it } from "vitest";

import {
  buildClientAssertionClaims,
  clientAssertionAuthenticationHeaders,
  createInMemorySessionCredentialStore,
  createInMemoryAgentIdentityStore,
  createInMemoryPublicDocumentCache,
  createInMemoryInspectCache,
  createAepAgent,
  createPlatformIdentityProvider,
  createJwtClientAssertionSigner,
  createPlatformDelegatedSigner,
  credentialPresentationHeaders,
  discoverPlatform,
  enrollService,
  fetchProtectedResource,
  fetchAepPublicDocument,
  grantService,
  inspectService,
  inspectOpenApiPolicy,
  interpretAepOpenApiOperation,
  probeProtectedResource,
  provisionPlatformIdentity,
  revokeService,
  resolveServiceReference,
  selectGrantType,
  sessionCredentialRecordFromGrantResult,
  signClientAssertion,
  AepPendingSignError,
  AepPendingSignResolverError,
  AepClaimValuesError,
  AepClaimRequirementsError,
  protectedResourceAuthenticationHeaders,
  statusService
} from "../src/index.js";
import type {
  AepAgent,
  AepClientAssertionSigner,
  AepClientAssertionSignerContext,
  AepInspectError,
  AepSessionCredentialRecord,
  AepServiceSession,
  InspectServiceResult,
  ResponseLike
} from "../src/index.js";
import type { PlatformAgentIdentity } from "@aep-foundation/platform";

const minimalInspectDocument = {
  aep_version: "1.0",
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
    grant_types_config: {
      "api-key": { supports_per_credential_revoke: "true" },
      basic: { supports_per_credential_revoke: "true" },
      "oauth-bearer": { supports_per_credential_revoke: "true" }
    },
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
} satisfies InspectDocument;

const minimalPlatformDiscoveryDocument = {
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
    algorithms: ["ES256"],
    default_lifetime_seconds: "300"
  }
};

describe("@aep-foundation/agent Inspect client", () => {
  it("normalizes URL, hostname, loopback, and did:web Service references", () => {
    expect(String(resolveServiceReference("api.example.com/path"))).toBe(
      "https://api.example.com/"
    );
    expect(String(resolveServiceReference("did:web:api.example.com:services:one"))).toBe(
      "https://api.example.com/"
    );
    expect(String(resolveServiceReference("http://localhost:3000/path"))).toBe(
      "http://localhost:3000/"
    );
    expect(() => resolveServiceReference("did:web:")).toThrow("Invalid AEP Service reference");
    expect(() => resolveServiceReference("https://user:secret@api.example.com")).toThrow(
      "must not contain credentials"
    );
    expect(() => resolveServiceReference("http://api.example.com")).toThrow("require HTTPS");
  });

  it("reuses fresh cached Inspect documents and refetches expired entries", async () => {
    let calls = 0;
    const cache = createInMemoryInspectCache();
    const fetch = () => {
      calls += 1;
      return jsonResponsePromise(minimalInspectDocument, {
        headers: { "cache-control": "max-age=300" }
      });
    };

    await withFetch(fetch, () =>
      inspectService({
        clock: () => new Date("2026-01-01T00:00:00.000Z"),
        inspectCache: cache,
        serviceUrl: "https://api.example.com"
      })
    );
    await withFetch(fetch, () =>
      inspectService({
        clock: () => new Date("2026-01-01T00:04:59.000Z"),
        inspectCache: cache,
        serviceUrl: "https://api.example.com"
      })
    );
    await withFetch(fetch, () =>
      inspectService({
        clock: () => new Date("2026-01-01T00:05:00.000Z"),
        inspectCache: cache,
        serviceUrl: "https://api.example.com"
      })
    );

    expect(calls).toBe(2);
  });

  it("does not cache Inspect responses marked no-store", async () => {
    let calls = 0;
    const cache = createInMemoryInspectCache();
    const fetch = () => {
      calls += 1;
      return jsonResponsePromise(minimalInspectDocument, {
        headers: { "cache-control": "no-store" }
      });
    };

    await withFetch(fetch, () =>
      inspectService({ inspectCache: cache, serviceUrl: "https://api.example.com" })
    );
    await withFetch(fetch, () =>
      inspectService({ inspectCache: cache, serviceUrl: "https://api.example.com" })
    );

    expect(calls).toBe(2);
  });

  it("conditionally revalidates an expired Inspect document", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const cache = createInMemoryInspectCache();
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      if (calls.length === 1)
        return jsonResponsePromise(minimalInspectDocument, {
          headers: { "cache-control": "max-age=1", etag: '"inspect-1"' }
        });
      return jsonResponsePromise(
        {},
        { ok: false, status: 304, headers: { "cache-control": "max-age=300" } }
      );
    };

    await withFetch(fetch, () =>
      inspectService({
        clock: () => new Date("2026-01-01T00:00:00.000Z"),
        inspectCache: cache,
        serviceUrl: "https://api.example.com"
      })
    );
    const result = await withFetch(fetch, () =>
      inspectService({
        clock: () => new Date("2026-01-01T00:00:02.000Z"),
        inspectCache: cache,
        serviceUrl: "https://api.example.com"
      })
    );

    expect(calls[1]?.init?.headers).toMatchObject({ "If-None-Match": '"inspect-1"' });
    expect(result.document.service.did).toBe("did:web:api.example.com");
    expect(result.cacheControl).toBe("max-age=300");
  });

  it("fetches and validates a Service Inspect document", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      return jsonResponsePromise(minimalInspectDocument, {
        headers: {
          "cache-control": "max-age=300",
          etag: '"inspect-1"'
        }
      });
    };

    const result = await withFetch(fetch, () =>
      inspectService({
        serviceUrl: "https://api.example.com/products?ignored=true"
      })
    );

    expect(String(calls[0]?.input)).toBe("https://api.example.com/.well-known/aep");
    expect(calls[0]?.init?.headers).toEqual({
      Accept: "application/aep+json"
    });
    expect(result.document.service.did).toBe("did:web:api.example.com");
    expect(String(result.inspectUrl)).toBe("https://api.example.com/.well-known/aep");
    expect(String(result.commandUrl("enroll"))).toBe("https://api.example.com/aep/enroll");
    expect(String(result.commandUrl("status"))).toBe("https://api.example.com/aep/status");
    expect(result.cacheControl).toBe("max-age=300");
    expect(result.etag).toBe('"inspect-1"');
  });

  it("accepts path-bearing did:web Service identities on the Inspect origin", async () => {
    const document = {
      ...minimalInspectDocument,
      service: { did: "did:web:api.example.com:services:primary" }
    } satisfies InspectDocument;

    const result = await withFetch(
      () => jsonResponsePromise(document),
      () => inspectService({ serviceUrl: "https://api.example.com" })
    );

    expect(result.document.service.did).toBe("did:web:api.example.com:services:primary");
  });

  it("rejects and evicts a did:web Service identity from another origin", async () => {
    let calls = 0;
    const cache = createInMemoryPublicDocumentCache();
    const document = {
      ...minimalInspectDocument,
      service: { did: "did:web:other.example.com" }
    } satisfies InspectDocument;
    const inspect = () =>
      withFetch(
        () => {
          calls += 1;
          return jsonResponsePromise(document, { headers: { "cache-control": "max-age=300" } });
        },
        () =>
          inspectService({
            publicDocumentCache: cache,
            serviceUrl: "https://api.example.com"
          })
      );

    await expect(inspect()).rejects.toMatchObject({ code: "service_identity_mismatch" });
    await expect(inspect()).rejects.toMatchObject({ code: "service_identity_mismatch" });
    expect(calls).toBe(2);
  });

  it("rejects a Service DID method without a supported origin binding", async () => {
    const document = {
      ...minimalInspectDocument,
      service: { did: "did:key:example" }
    } satisfies InspectDocument;

    await expect(
      withFetch(
        () => jsonResponsePromise(document),
        () => inspectService({ serviceUrl: "https://api.example.com" })
      )
    ).rejects.toMatchObject({ code: "service_identity_mismatch" });
  });

  it("throws AepInspectError on non-2xx responses", async () => {
    await expect(
      withFetch(
        () =>
          jsonResponsePromise(
            {
              code: "not_found"
            },
            {
              ok: false,
              status: 404,
              statusText: "Not Found"
            }
          ),
        () =>
          inspectService({
            serviceUrl: "https://api.example.com"
          })
      )
    ).rejects.toMatchObject({
      name: "AepInspectError",
      status: 404
    } satisfies Partial<AepInspectError>);
  });

  it("throws a typed Inspect error on invalid response bodies", async () => {
    await expect(
      withFetch(
        () =>
          jsonResponsePromise({
            aep_version: "bad"
          }),
        () =>
          inspectService({
            serviceUrl: "https://api.example.com"
          })
      )
    ).rejects.toMatchObject({ name: "AepInspectError", code: "validation_failed" });
  });

  it.each([
    ["missing redirect location", { status: 302, headers: {} }, "invalid_redirect"],
    [
      "cross-origin redirect",
      { status: 302, headers: { location: "https://other.example/.well-known/aep" } },
      "invalid_redirect"
    ],
    [
      "invalid media type",
      { status: 200, headers: { "content-type": "application/json" } },
      "invalid_media_type"
    ]
  ])("rejects %s", async (_name, responseOptions, code) => {
    await expect(
      withFetch(
        () => jsonResponsePromise(minimalInspectDocument, responseOptions),
        () => inspectService({ serviceUrl: "https://api.example.com" })
      )
    ).rejects.toMatchObject({ code });
  });

  it("bounds redirects and response bytes and reports malformed transport data", async () => {
    let redirects = 0;
    await expect(
      withFetch(
        () => {
          redirects += 1;
          return jsonResponsePromise(
            {},
            { status: 302, headers: { location: `/redirect-${redirects}` } }
          );
        },
        () => inspectService({ serviceUrl: "https://api.example.com" })
      )
    ).rejects.toMatchObject({ code: "invalid_redirect" });

    await expect(
      withFetch(
        () => Promise.reject(new Error("aborted")),
        () => inspectService({ serviceUrl: "https://api.example.com" })
      )
    ).rejects.toMatchObject({ code: "aborted" });

    await expect(
      withFetch(
        () =>
          Promise.resolve({
            ...jsonResponse(minimalInspectDocument),
            text: () => Promise.resolve("not-json")
          }),
        () => inspectService({ serviceUrl: "https://api.example.com" })
      )
    ).rejects.toMatchObject({ code: "invalid_json" });

    await expect(
      withFetch(
        () =>
          Promise.resolve({
            ...jsonResponse(minimalInspectDocument),
            text: () => Promise.resolve(JSON.stringify(minimalInspectDocument))
          }),
        () => inspectService({ maxResponseBytes: 10, serviceUrl: "https://api.example.com" })
      )
    ).rejects.toMatchObject({ code: "response_too_large" });

    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(JSON.stringify(minimalInspectDocument)));
        controller.close();
      }
    });
    await expect(
      withFetch(
        () => Promise.resolve({ ...jsonResponse(minimalInspectDocument), body }),
        () => inspectService({ maxResponseBytes: 10, serviceUrl: "https://api.example.com" })
      )
    ).rejects.toMatchObject({ code: "response_too_large" });
  });

  it("requires a fetch implementation", async () => {
    const previousFetch = globalThis.fetch;

    try {
      Object.defineProperty(globalThis, "fetch", {
        configurable: true,
        value: undefined
      });

      await expect(
        inspectService({
          serviceUrl: "https://api.example.com"
        })
      ).rejects.toThrow("fetch implementation");
    } finally {
      Object.defineProperty(globalThis, "fetch", {
        configurable: true,
        value: previousFetch
      });
    }
  });
});

describe("@aep-foundation/agent command clients", () => {
  it("returns completed asynchronous signing and exposes pending signing as a typed error", async () => {
    const base = {
      agentDid: "did:web:agent.example.com:agents:123",
      clock: () => new Date("2026-05-28T12:00:00.000Z"),
      command: "status" as const,
      jti: "status-jti",
      serviceDid: "did:web:api.example.com"
    };

    await expect(
      signClientAssertion({
        ...base,
        signer: () => ({ status: "completed", clientAssertion: "completed.jwt" })
      })
    ).resolves.toBe("completed.jwt");

    const pending = signClientAssertion({
      ...base,
      signer: () => ({
        status: "pending",
        platformContext: { continuation: "opaque" },
        retryAfterSeconds: 5
      })
    });
    await expect(pending).rejects.toBeInstanceOf(AepPendingSignError);
    await expect(pending).rejects.toMatchObject({
      result: { retryAfterSeconds: 5, status: "pending" }
    });
  });

  it("builds and signs baseline client assertions", async () => {
    const claims = buildClientAssertionClaims({
      agentDid: "did:web:agent.example.com:agents:123",
      clock: () => new Date("2026-05-28T12:00:00.000Z"),
      command: "grant",
      jti: "grant-jti",
      serviceDid: "did:web:api.example.com",
      ttlSeconds: 120
    });

    expect(claims).toEqual({
      aud: "did:web:api.example.com",
      exp: 1779969720,
      iat: 1779969600,
      iss: "did:web:agent.example.com:agents:123",
      jti: "grant-jti",
      op: "grant",
      sub: "did:web:agent.example.com:agents:123"
    });

    expect(() =>
      buildClientAssertionClaims({
        agentDid: "did:web:agent.example.com:agents:123",
        command: "status",
        serviceDid: "did:web:api.example.com",
        ttlSeconds: 301
      })
    ).toThrow("between 1 and 300 seconds");

    await expect(
      signClientAssertion({
        agentDid: "did:web:agent.example.com:agents:123",
        clock: () => new Date("2026-05-28T12:00:00.000Z"),
        command: "status",
        idempotencyKey: "status-sign-key",
        jti: "status-jti",
        serviceDid: "did:web:api.example.com",
        signer: (signedClaims, context) =>
          JSON.stringify({
            context,
            signedClaims
          })
      })
    ).resolves.toBe(
      JSON.stringify({
        context: {
          command: "status",
          idempotencyKey: "status-sign-key",
          serviceDid: "did:web:api.example.com",
          signingAlgorithms: ["EdDSA", "ES256"]
        },
        signedClaims: {
          aud: "did:web:api.example.com",
          exp: 1779969900,
          iat: 1779969600,
          iss: "did:web:agent.example.com:agents:123",
          jti: "status-jti",
          op: "status",
          sub: "did:web:agent.example.com:agents:123"
        }
      })
    );
  });

  it.each(["grant", "authenticate"] as const)(
    "continues pending %s signing with opaque context and a new stable stage key",
    async (command) => {
      const contexts: Array<{
        idempotencyKey?: string;
        platformContext?: Record<string, unknown>;
      }> = [];
      let calls = 0;
      const signer: AepClientAssertionSigner = (_claims, context) => {
        contexts.push(context);
        calls += 1;
        if (calls === 1) {
          return {
            status: "pending",
            platformContext: { opaque: { continuation: "secret" } },
            retryAfterSeconds: 7
          };
        }
        if (calls === 2) {
          return {
            status: "pending",
            platformContext: { opaque: { continuation: "secret" } },
            retryAfterSeconds: 7
          };
        }
        return { status: "completed", clientAssertion: `${command}.jwt` };
      };

      await expect(
        signClientAssertion({
          agentDid: "did:web:agent.example.com:agents:123",
          command,
          jti: `${command}-jti`,
          pendingSignResolver: async (input) => {
            const { pending } = input;
            expect(pending).toEqual({
              status: "pending",
              platformContext: { opaque: { continuation: "secret" } },
              retryAfterSeconds: 7
            });
            expect((await input.continueSign()).status).toBe("pending");
            const completed = await input.continueSign();
            if (completed.status !== "completed") throw new Error("Expected completion.");
            return completed;
          },
          ...(command === "authenticate" ? { resource: "https://api.example.com/items" } : {}),
          serviceDid: "did:web:api.example.com",
          signer
        })
      ).resolves.toBe(`${command}.jwt`);

      expect(contexts).toHaveLength(3);
      expect(contexts[0]?.idempotencyKey).not.toBe(contexts[1]?.idempotencyKey);
      expect(contexts[1]?.idempotencyKey).toBe(contexts[2]?.idempotencyKey);
      expect(contexts[1]?.platformContext).toEqual({
        opaque: { continuation: "secret" }
      });
      expect(contexts[2]?.platformContext).toEqual({
        opaque: { continuation: "secret" }
      });
    }
  );

  it("preserves direct pending errors and types resolver failures and cancellation", async () => {
    const pendingSigner: AepClientAssertionSigner = () => ({
      status: "pending",
      platformContext: { opaque: true },
      retryAfterSeconds: 3
    });
    const base = {
      agentDid: "did:web:agent.example.com:agents:123",
      command: "grant" as const,
      serviceDid: "did:web:api.example.com",
      signer: pendingSigner
    };
    await expect(signClientAssertion(base)).rejects.toBeInstanceOf(AepPendingSignError);

    await expect(
      signClientAssertion({
        ...base,
        pendingSignResolver: () => {
          throw new AepPendingSignResolverError("The caller declined signing.", "declined");
        }
      })
    ).rejects.toMatchObject({ code: "declined" });

    const controller = new AbortController();
    await expect(
      signClientAssertion({
        ...base,
        pendingSignResolver: ({ signal }) => {
          controller.abort();
          signal?.throwIfAborted();
          throw new Error("unreachable");
        },
        signal: controller.signal
      })
    ).rejects.toMatchObject({ code: "aborted" });
  });

  it("creates a JWT client assertion signer", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: {
        format: "pem",
        type: "pkcs8"
      },
      publicKeyEncoding: {
        format: "pem",
        type: "spki"
      }
    });
    const signer = createJwtClientAssertionSigner({
      alg: "ES256",
      key: {
        format: "pkcs8",
        pem: privateKey
      },
      kid: "did:web:agent.example.com:agents:123#key-1"
    });
    const jwt = await signClientAssertion({
      agentDid: "did:web:agent.example.com:agents:123",
      clock: () => new Date("2026-05-28T12:00:00.000Z"),
      command: "status",
      jti: "status-jwt",
      serviceDid: "did:web:api.example.com",
      signer
    });

    await expect(
      verifyClientAssertionJwt(jwt, {
        algorithms: ["ES256"],
        audience: "did:web:api.example.com",
        currentDate: new Date("2026-05-28T12:00:00.000Z"),
        key: {
          format: "spki",
          pem: publicKey
        }
      })
    ).resolves.toMatchObject({
      aud: "did:web:api.example.com",
      jti: "status-jwt",
      op: "status",
      sub: "did:web:agent.example.com:agents:123"
    });

    const loopbackSigner = createJwtClientAssertionSigner({
      alg: "ES256",
      allowInsecureLoopback: true,
      key: {
        format: "pkcs8",
        pem: privateKey
      },
      kid: "did:web:agent.example.com:agents:123#key-1"
    });
    const loopbackJwt = await signClientAssertion({
      agentDid: "did:web:agent.example.com:agents:123",
      allowInsecureLoopback: true,
      clock: () => new Date("2026-05-28T12:00:00.000Z"),
      command: "authenticate",
      jti: "authenticate-loopback-jwt",
      resource: "http://127.0.0.1:3000/api/resource",
      serviceDid: "did:web:api.example.com",
      signer: loopbackSigner
    });

    await expect(
      verifyClientAssertionJwt(loopbackJwt, {
        algorithms: ["ES256"],
        allowInsecureLoopback: true,
        audience: "did:web:api.example.com",
        currentDate: new Date("2026-05-28T12:00:00.000Z"),
        key: {
          format: "spki",
          pem: publicKey
        }
      })
    ).resolves.toMatchObject({
      jti: "authenticate-loopback-jwt",
      resource: "http://127.0.0.1:3000/api/resource"
    });
  });

  it("posts Enroll requests using Inspect command metadata", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      return jsonResponsePromise({
        status: "active"
      });
    };

    const result = await withFetch(fetch, () =>
      enrollService({
        agentDid: "did:web:agent.example.com:agents:123",
        claims: {
          "contact.email": "ops@example.com"
        },
        clientAssertion: "jwt.enroll",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
        inspect: inspectResult(),
        serviceUrl: "https://api.example.com"
      })
    );

    expect(String(calls[0]?.input)).toBe("https://api.example.com/aep/enroll");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[0]?.init?.headers).toEqual({
      Accept: "application/aep+json",
      Authorization: "AEP jwt.enroll",
      "Content-Type": "application/aep+json",
      "Idempotency-Key": "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
    });
    expect(JSON.parse(requestBody(calls[0]?.init?.body))).toEqual({
      agent_did: "did:web:agent.example.com:agents:123",
      claims: {
        "contact.email": "ops@example.com"
      },
      idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
    });
    expect(result).toEqual({
      body: {
        status: "active"
      },
      commandUrl: new URL("https://api.example.com/aep/enroll"),
      status: 200
    });
  });

  it("rejects malformed and missing required Claim Values before sending Enroll", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      return jsonResponsePromise({ status: "active" });
    };
    const requiredClaimsInspect = inspectResult({
      ...minimalInspectDocument,
      claims: {
        ...minimalInspectDocument.claims,
        required: ["contact.email"]
      }
    });

    const malformedClaimValues = withFetch(fetch, () =>
      enrollService({
        agentDid: "did:web:agent.example.com:agents:123",
        claims: { "contact.email": "not-email" },
        clientAssertion: "jwt.enroll",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
        inspect: requiredClaimsInspect,
        serviceUrl: "https://api.example.com"
      })
    );
    await expect(malformedClaimValues).rejects.toBeInstanceOf(AepClaimValuesError);
    await expect(malformedClaimValues).rejects.toEqual(
      expect.objectContaining({
        issues: [{ message: "Expected an RFC 5321 Mailbox.", path: "$.contact.email" }],
        name: "AepClaimValuesError"
      })
    );

    const missingRequiredEnrollment = withFetch(fetch, () =>
      enrollService({
        agentDid: "did:web:agent.example.com:agents:123",
        clientAssertion: "jwt.enroll",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000001",
        inspect: requiredClaimsInspect,
        serviceUrl: "https://api.example.com"
      })
    );
    await expect(missingRequiredEnrollment).rejects.toBeInstanceOf(AepClaimRequirementsError);
    await expect(missingRequiredEnrollment).rejects.toEqual(
      expect.objectContaining({
        missingRequiredClaimNames: ["contact.email"],
        name: "AepClaimRequirementsError"
      })
    );

    expect(calls).toEqual([]);
  });

  it("gets Status requests without a body", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      return jsonResponsePromise({
        owner_action_required: "false",
        since: "2026-05-28T12:00:00Z",
        status: "active"
      });
    };

    const result = await withFetch(fetch, () =>
      statusService({
        clientAssertion: "jwt.status",
        inspect: inspectResult(),
        serviceUrl: "https://api.example.com"
      })
    );

    expect(String(calls[0]?.input)).toBe("https://api.example.com/aep/status");
    expect(calls[0]?.init).toEqual({
      headers: {
        Accept: "application/aep+json",
        Authorization: "AEP jwt.status"
      },
      method: "GET"
    });
    expect(result.body.status).toBe("active");
  });

  it("posts Grant requests using Inspect command metadata", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      return jsonResponsePromise({
        access_token: "access-token",
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        scopes: ["read"],
        token_type: "Bearer"
      });
    };

    const result = await withFetch(fetch, () =>
      grantService({
        clientAssertion: "jwt.grant",
        grantType: "oauth-bearer",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-grant0000000",
        inspect: inspectResult(),
        requestedScopes: ["read"],
        serviceUrl: "https://api.example.com"
      })
    );

    expect(String(calls[0]?.input)).toBe("https://api.example.com/aep/grant");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[0]?.init?.headers).toEqual({
      Accept: "application/aep+json",
      Authorization: "AEP jwt.grant",
      "Content-Type": "application/aep+json",
      "Idempotency-Key": "9f8a4d2e-1c3b-4f5e-8b7a-grant0000000"
    });
    expect(JSON.parse(requestBody(calls[0]?.init?.body))).toEqual({
      grant_type: "oauth-bearer",
      requested_scopes: ["read"]
    });
    expect(result).toEqual({
      body: {
        access_token: "access-token",
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        scopes: ["read"],
        token_type: "Bearer"
      },
      commandUrl: new URL("https://api.example.com/aep/grant"),
      status: 200
    });
  });

  it("normalizes null API-key Grant scopes", async () => {
    const result = await withFetch(
      () =>
        jsonResponsePromise({
          api_key: "api-key",
          credential_id: "cred_123",
          expires_at: "2026-05-28T12:00:00Z",
          header: "X-API-Key",
          scopes: null
        }),
      () =>
        grantService({
          clientAssertion: "jwt.grant",
          grantType: "api-key",
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-grant0000001",
          inspect: inspectResult(),
          serviceUrl: "https://api.example.com"
        })
    );

    expect(result.body).toMatchObject({
      header: "X-API-Key",
      scopes: []
    });
  });

  it("posts Revoke requests using exactly one selector", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      return jsonResponsePromise({});
    };

    const result = await withFetch(fetch, () =>
      revokeService({
        allGrantTypes: true,
        clientAssertion: "jwt.revoke",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-revoke000000",
        inspect: inspectResult(),
        serviceUrl: "https://api.example.com"
      })
    );

    expect(String(calls[0]?.input)).toBe("https://api.example.com/aep/revoke");
    expect(calls[0]?.init).toEqual({
      body: JSON.stringify({
        all_grant_types: "true"
      }),
      headers: {
        Accept: "application/aep+json",
        Authorization: "AEP jwt.revoke",
        "Content-Type": "application/aep+json",
        "Idempotency-Key": "9f8a4d2e-1c3b-4f5e-8b7a-revoke000000"
      },
      method: "POST"
    });
    expect(result).toEqual({
      body: {},
      commandUrl: new URL("https://api.example.com/aep/revoke"),
      status: 200
    });
  });

  it("requires advertised per-credential Revoke before targeting a credential", async () => {
    await expect(
      revokeService({
        clientAssertion: "jwt.revoke",
        credentialId: "cred_123",
        grantType: "oauth-bearer",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-revoke000000",
        inspect: inspectResult({
          ...minimalInspectDocument,
          commands: {
            grant_types: ["oauth-bearer"],
            supported: ["inspect", "revoke"]
          }
        }),
        serviceUrl: "https://api.example.com"
      })
    ).rejects.toThrow("does not advertise per-credential Revoke");
  });

  it("can inspect before sending commands", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const fetch = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));

      if (String(input).endsWith("/.well-known/aep")) {
        return jsonResponsePromise(minimalInspectDocument);
      }

      return jsonResponsePromise({
        status: "active"
      });
    };

    await withFetch(fetch, () =>
      enrollService({
        agentDid: "did:web:agent.example.com:agents:123",
        claims: {
          "contact.email": "agent@example.com"
        },
        clientAssertion: "jwt.enroll",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
        serviceUrl: "https://api.example.com"
      })
    );

    expect(calls.map((call) => String(call.input))).toEqual([
      "https://api.example.com/.well-known/aep",
      "https://api.example.com/aep/enroll"
    ]);
  });

  it("supports high-level service sessions on an agent instance", async () => {
    const signerEvents: string[] = [];
    const readCalls: string[] = [];
    const writeCalls: string[] = [];
    const signer: AepClientAssertionSigner = (claims) => {
      signerEvents.push(claims.op);
      return `jwt.${claims.op}.${claims.jti}`;
    };
    const requestUrl = (input: Parameters<typeof globalThis.fetch>[0]) =>
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const response = (input: Parameters<typeof globalThis.fetch>[0]) => {
      const url = requestUrl(input);
      const body = url.endsWith("/.well-known/aep")
        ? minimalInspectDocument
        : url.endsWith("/grant")
          ? {
              access_token: "access-token",
              credential_id: "cred_123",
              expires_at: "2999-05-28T12:00:00Z",
              scopes: [],
              token_type: "Bearer"
            }
          : url.endsWith("/revoke")
            ? {}
            : url.endsWith("/status")
              ? {
                  owner_action_required: "false",
                  since: "2026-05-28T12:00:00Z",
                  status: "active"
                }
              : {
                  status: "active"
                };
      return Promise.resolve(
        new Response(JSON.stringify(body), { headers: { "content-type": AEP_MEDIA_TYPE } })
      );
    };
    const readFetch: typeof globalThis.fetch = (input) => {
      readCalls.push(requestUrl(input));
      return response(input);
    };
    const writeFetch: typeof globalThis.fetch = (input) => {
      writeCalls.push(requestUrl(input));
      return response(input);
    };
    const credentialStore = createInMemorySessionCredentialStore();
    const agent = createAepAgent({
      assertionClock: () => new Date("2026-05-28T12:00:00.000Z"),
      assertionJti: () => `jti-${signerEvents.length + 1}`,
      credentialStore,
      identityProvider: {
        getOrCreateIdentity: () => ({
          agentDid: "did:web:agent.example.com:agents:123",
          identityKind: "sovereign",
          serviceDid: "did:web:api.example.com",
          signingAlgorithms: ["ES256"]
        }),
        signerFor: () => signer
      },
      readFetch,
      writeFetch
    });
    const session = agent.serviceSession({
      serviceUrl: "https://api.example.com"
    });

    await expect(
      session.enroll({
        claims: {
          "contact.email": "agent@example.com"
        },
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      })
    ).resolves.toMatchObject({
      body: {
        status: "active"
      }
    });

    await expect(session.status()).resolves.toMatchObject({
      body: {
        status: "active"
      }
    });

    await expect(
      session.grant({
        grantType: "oauth-bearer",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-agentgrant"
      })
    ).resolves.toMatchObject({
      body: {
        credential_id: "cred_123"
      }
    });

    await expect(
      session.revoke({
        credentialId: "cred_123",
        grantType: "oauth-bearer",
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-agentrevoke"
      })
    ).resolves.toMatchObject({
      body: {}
    });
    expect(signerEvents).toEqual(["enroll", "status", "grant", "revoke"]);
    expect(readCalls).toEqual([
      "https://api.example.com/.well-known/aep",
      "https://api.example.com/aep/status"
    ]);
    expect(writeCalls).toEqual([
      "https://api.example.com/aep/enroll",
      "https://api.example.com/aep/grant",
      "https://api.example.com/aep/revoke"
    ]);
    expect(await credentialStore.listCredentials("did:web:api.example.com")).toEqual([]);
  });

  it("removes locally stored credentials after bulk Revoke succeeds", async () => {
    const serviceDid = "did:web:api.example.com";
    const credentialStore = createInMemorySessionCredentialStore([
      sessionCredentialRecord("oauth-1", "oauth-bearer"),
      sessionCredentialRecord("oauth-2", "oauth-bearer"),
      sessionCredentialRecord("api-key-1", "api-key")
    ]);
    const fetch: typeof globalThis.fetch = (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      return Promise.resolve(
        new Response(
          JSON.stringify(url.endsWith("/.well-known/aep") ? minimalInspectDocument : {}),
          {
            headers: { "content-type": AEP_MEDIA_TYPE }
          }
        )
      );
    };
    const agent = createAepAgent({
      credentialStore,
      fetch,
      identityProvider: {
        getOrCreateIdentity: () => ({
          agentDid: "did:web:agent.example.com:agents:123",
          identityKind: "sovereign",
          serviceDid,
          signingAlgorithms: ["ES256"]
        }),
        signerFor: () => () => "jwt.revoke"
      }
    });
    const session = agent.serviceSession({ serviceUrl: "https://api.example.com" });

    await session.revoke({ grantType: "oauth-bearer" });
    expect(await credentialStore.listCredentials(serviceDid)).toMatchObject([
      { credentialId: "api-key-1", grantType: "api-key" }
    ]);

    await session.revoke({ allGrantTypes: true });
    expect(await credentialStore.listCredentials(serviceDid)).toEqual([]);
  });

  it("does not infer protected-resource authentication methods", async () => {
    const agent = createAepAgent({
      credentialStore: createInMemorySessionCredentialStore(),
      fetch: () => fetchJsonResponse(minimalInspectDocument),
      identityProvider: {
        getOrCreateIdentity: () => ({
          agentDid: "did:web:agent.example.com:agents:123",
          identityKind: "sovereign",
          serviceDid: "did:web:api.example.com",
          signingAlgorithms: ["ES256"]
        }),
        signerFor: () => () => "jwt.authenticate"
      }
    });

    await expect(
      agent.serviceSession({ serviceUrl: "https://api.example.com" }).authenticationHeaders()
    ).rejects.toThrow("does not advertise AEP JWT authentication");
  });

  it("uses only advertised credentials in Service preference order", async () => {
    const credentialStore = createInMemorySessionCredentialStore([
      sessionCredentialRecord("oauth-1", "oauth-bearer"),
      sessionCredentialRecord("api-key-1", "api-key")
    ]);
    const document: InspectDocument = {
      ...minimalInspectDocument,
      authentication: { methods: ["api-key", "oauth-bearer"] }
    };
    const agent = createAepAgent({
      credentialStore,
      fetch: () => fetchJsonResponse(document),
      identityProvider: {
        getOrCreateIdentity: () => ({
          agentDid: "did:web:agent.example.com:agents:123",
          identityKind: "sovereign",
          serviceDid: "did:web:api.example.com",
          signingAlgorithms: ["ES256"]
        }),
        signerFor: () => () => "jwt.authenticate"
      }
    });
    const session = agent.serviceSession({ serviceUrl: "https://api.example.com" });

    await expect(session.authenticationHeaders()).resolves.toEqual({
      "X-API-Key": "api-key"
    });
    const restrictedAgent = createAepAgent({
      credentialStore,
      fetch: () =>
        fetchJsonResponse({
          ...minimalInspectDocument,
          authentication: { methods: ["api-key"] }
        }),
      identityProvider: {
        getOrCreateIdentity: () => ({
          agentDid: "did:web:agent.example.com:agents:123",
          identityKind: "sovereign",
          serviceDid: "did:web:api.example.com",
          signingAlgorithms: ["ES256"]
        }),
        signerFor: () => () => "jwt.authenticate"
      }
    });
    const restricted = restrictedAgent.serviceSession({
      serviceUrl: "https://api.example.com"
    });
    await expect(restricted.authenticationHeaders({ credentialId: "oauth-1" })).rejects.toThrow(
      "does not advertise oauth-bearer authentication"
    );
    await expect(restricted.authenticationHeaders({ grantType: "basic" })).rejects.toThrow(
      "does not advertise basic authentication"
    );
    await expect(restricted.authenticationHeaders({ credentialId: "missing" })).rejects.toThrow(
      "Stored AEP credential was not found"
    );
    await credentialStore.deleteCredential("did:web:api.example.com", "oauth-1");
    await expect(session.authenticationHeaders({ grantType: "oauth-bearer" })).rejects.toThrow(
      "Stored oauth-bearer credential was not found"
    );
  });

  it("throws AepCommandError with Problem Details on command failures", async () => {
    await expect(
      withFetch(
        () =>
          jsonResponsePromise(
            {
              code: "not_recognized",
              status: 401,
              title: "Not recognized",
              type: "urn:aep:error:not_recognized"
            },
            {
              ok: false,
              status: 401,
              statusText: "Unauthorized"
            }
          ),
        () =>
          statusService({
            clientAssertion: "jwt.status",
            inspect: inspectResult(),
            serviceUrl: "https://api.example.com"
          })
      )
    ).rejects.toMatchObject({
      name: "AepCommandError",
      problem: {
        code: "not_recognized"
      },
      status: 401
    });
  });

  it("rejects commands not advertised by Inspect", async () => {
    await expect(
      withFetch(
        () => jsonResponsePromise({ status: "active" }),
        () =>
          enrollService({
            agentDid: "did:web:agent.example.com:agents:123",
            clientAssertion: "jwt.enroll",
            idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
            inspect: inspectResult({
              ...minimalInspectDocument,
              commands: {
                supported: ["inspect", "status"]
              }
            }),
            serviceUrl: "https://api.example.com"
          })
      )
    ).rejects.toThrow("does not advertise enroll");
  });
});

describe("@aep-foundation/agent protected-resource pending Sign continuation", () => {
  it("preserves identity-provider failures for JWT protected resources", async () => {
    const missingIdentity = new Error("identity not enrolled");
    const agent = createAepAgent({
      identityProvider: {
        getOrCreateIdentity: () => {
          throw missingIdentity;
        },
        signerFor: () => () => "jwt.authenticate"
      }
    });

    await withFetch(
      (input) => {
        const url = String(input);
        if (url.endsWith("/.well-known/aep")) {
          return jsonResponsePromise({
            ...minimalInspectDocument,
            authentication: { methods: ["aep-jwt"] }
          });
        }
        return jsonResponsePromise(
          {},
          {
            headers: {
              "www-authenticate":
                'AEP service_did="did:web:api.example.com", inspect="https://api.example.com/.well-known/aep"'
            },
            ok: false,
            status: 401
          }
        );
      },
      async () => {
        await expect(
          fetchProtectedResource({ agent, url: "https://api.example.com/items" })
        ).rejects.toBe(missingIdentity);
      }
    );
  });

  it.each(["grant", "authenticate"] as const)(
    "keeps fetchProtectedResource alive through pending %s signing",
    async (pendingOperation) => {
      const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
      const signCalls: AepClientAssertionSignerContext[] = [];
      const platformContextCalls: string[] = [];
      let resolverCalls = 0;
      let operationCalls = 0;
      const signer: AepClientAssertionSigner = (claims, context) => {
        signCalls.push(context);
        if (claims.op !== pendingOperation) return `jwt.${claims.op}`;
        operationCalls += 1;
        return operationCalls === 1
          ? {
              status: "pending",
              platformContext: { opaque: `${pendingOperation}-continuation` },
              retryAfterSeconds: 2
            }
          : { status: "completed", clientAssertion: `jwt.${pendingOperation}` };
      };
      const inspect = {
        ...minimalInspectDocument,
        authentication: {
          methods: pendingOperation === "authenticate" ? ["aep-jwt"] : ["oauth-bearer"]
        }
      } satisfies InspectDocument;
      const agent = createAepAgent({
        identityStore: createInMemoryAgentIdentityStore([
          {
            agentDid: "did:web:agent.example.com:agents:123",
            identityKind: "sovereign",
            serviceDid: "did:web:api.example.com",
            signingAlgorithms: ["ES256"]
          }
        ]),
        identityProvider: {
          getOrCreateIdentity: () => ({
            agentDid: "did:web:agent.example.com:agents:123",
            identityKind: "sovereign",
            serviceDid: "did:web:api.example.com",
            signingAlgorithms: ["ES256"]
          }),
          signerFor: () => signer
        },
        pendingSignResolver: async (input) => {
          const { pending } = input;
          resolverCalls += 1;
          expect(pending.platformContext).toEqual({
            opaque: `${pendingOperation}-continuation`
          });
          const completed = await input.continueSign();
          if (completed.status !== "completed") throw new Error("Expected completion.");
          return completed;
        },
        platformContextProvider: ({ command, grantType }) => {
          platformContextCalls.push(command);
          return command === "grant" ? { grant_type: grantType } : undefined;
        }
      });
      const fetch = (input: URL | string, init?: RequestInit): Promise<ResponseLike> => {
        calls.push(fetchCall(input, init));
        const url = String(input);
        if (url.endsWith("/.well-known/aep")) return jsonResponsePromise(inspect);
        if (url.endsWith("/aep/grant")) {
          return jsonResponsePromise({
            access_token: "access-token",
            credential_id: "cred_123",
            expires_at: "2999-05-28T12:00:00Z",
            scopes: [],
            token_type: "Bearer"
          });
        }
        if (url.endsWith("/aep/status")) return jsonResponsePromise({ status: "active" });
        const authorization = new Headers(init?.headers).get("authorization");
        if (authorization === null) {
          return jsonResponsePromise(
            {},
            {
              headers: {
                "www-authenticate":
                  'AEP service_did="did:web:api.example.com", inspect="https://api.example.com/.well-known/aep"'
              },
              ok: false,
              status: 401
            }
          );
        }
        return jsonResponsePromise({ ok: true });
      };

      const response = await withFetch(fetch, () =>
        fetchProtectedResource({
          agent,
          url: "https://api.example.com/items"
        })
      );

      expect(response.status).toBe(200);
      expect(resolverCalls).toBe(1);
      expect(operationCalls).toBe(2);
      expect(signCalls.filter((context) => context.command === pendingOperation)).toHaveLength(2);
      expect(platformContextCalls).toEqual(pendingOperation === "grant" ? ["grant"] : []);
      expect(calls.filter((call) => String(call.input).endsWith("/aep/grant"))).toHaveLength(
        pendingOperation === "grant" ? 1 : 0
      );
      const operationContexts = signCalls.filter((context) => context.command === pendingOperation);
      if (pendingOperation === "grant") {
        expect(operationContexts[0]?.platformContext).toEqual({ grant_type: "oauth-bearer" });
      }
      expect(operationContexts[0]?.idempotencyKey).not.toBe(operationContexts[1]?.idempotencyKey);
      expect(operationContexts[1]?.platformContext).toEqual({
        opaque: `${pendingOperation}-continuation`
      });
    }
  );
});

describe("@aep-foundation/agent public documents and OpenAPI", () => {
  it("fetches and interprets an advertised OpenAPI document", async () => {
    const inspect = inspectResult({
      ...minimalInspectDocument,
      http: {
        ...minimalInspectDocument.http,
        openapi: { path_matching: { trailing_slash: "strict" }, url: "/openapi.json" }
      }
    });
    const policy = await withFetch(
      () =>
        jsonResponsePromise(
          {
            openapi: "3.1.0",
            paths: { "/items": { get: { security: [] } } }
          },
          { headers: { "content-type": "application/json" } }
        ),
      () =>
        inspectOpenApiPolicy({
          inspect,
          maxResponseBytes: 10_000,
          method: "GET",
          publicDocumentCache: createInMemoryPublicDocumentCache(),
          signal: new AbortController().signal,
          url: "https://api.example.com/items"
        })
    );
    expect(policy).toMatchObject({ state: "public", freshness: "fetched" });
  });

  it("requires the OpenAPI 3.1 vendor media-type parameter", async () => {
    const inspect = inspectResult({
      ...minimalInspectDocument,
      http: {
        ...minimalInspectDocument.http,
        openapi: { path_matching: { trailing_slash: "strict" }, url: "/openapi.json" }
      }
    });
    const inspectPolicy = () =>
      inspectOpenApiPolicy({
        inspect,
        url: "https://api.example.com/items"
      });

    await expect(
      withFetch(
        () =>
          jsonResponsePromise(
            { openapi: "3.1.0", paths: {} },
            { headers: { "content-type": "application/vnd.oai.openapi+json" } }
          ),
        inspectPolicy
      )
    ).rejects.toThrow("media type");
    await expect(
      withFetch(
        () =>
          jsonResponsePromise(
            { openapi: "3.1.0", paths: {} },
            {
              headers: {
                "content-type": "application/vnd.oai.openapi+json; charset=utf-8; version=3.1"
              }
            }
          ),
        inspectPolicy
      )
    ).resolves.toMatchObject({ state: "fallback" });
  });

  it("shares fresh serializable documents and single-flights fetches", async () => {
    const cache = createInMemoryPublicDocumentCache();
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      await Promise.resolve();
      return new Response(JSON.stringify({ value: 1 }), {
        headers: { "cache-control": "max-age=300", "content-type": "application/json" }
      });
    };
    const run = () =>
      withFetch(fetcher, () =>
        fetchAepPublicDocument({
          accept: "application/json",
          acceptedMediaTypes: ["application/json"],
          cache,
          namespace: "openapi",
          parse: (value) => value,
          url: "https://api.example.com/openapi.json"
        })
      );
    const [first, second] = await Promise.all([run(), run()]);
    expect(first.value).toEqual({ value: 1 });
    expect(second.freshness).toBe("fetched");
    expect(calls).toBe(1);
    const cached = await run();
    expect(cached.freshness).toBe("fresh");
    expect(calls).toBe(1);
  });

  it("follows redirects, persists aliases, and conditionally revalidates public documents", async () => {
    const cache = createInMemoryPublicDocumentCache();
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    let response = 0;
    const fetcher = (input: URL | string, init?: RequestInit) => {
      calls.push(fetchCall(input, init));
      response += 1;
      if (response === 1)
        return Promise.resolve(
          new Response(null, { status: 302, headers: { location: "/documents/openapi.json" } })
        );
      if (response === 2)
        return jsonResponsePromise(
          { openapi: "3.1.0" },
          {
            headers: {
              "cache-control": "max-age=0",
              "content-type": "application/json",
              etag: '"openapi-1"',
              "last-modified": "Thu, 16 Jul 2026 12:00:00 GMT"
            }
          }
        );
      return Promise.resolve(
        new Response(null, { status: 304, headers: { "cache-control": "max-age=300" } })
      );
    };
    const options = {
      accept: "application/json",
      acceptedMediaTypes: ["application/json"],
      cache,
      clock: () => new Date("2026-07-16T12:05:00.000Z"),
      namespace: "openapi" as const,
      parse: (value: unknown) => value,
      sameOriginRedirects: true,
      url: "https://api.example.com/openapi.json"
    };

    const fetched = await withFetch(fetcher, () => fetchAepPublicDocument(options));
    const revalidated = await withFetch(fetcher, () => fetchAepPublicDocument(options));

    expect(fetched.finalUrl.href).toBe("https://api.example.com/documents/openapi.json");
    expect(revalidated).toMatchObject({ freshness: "revalidated", value: { openapi: "3.1.0" } });
    expect(calls[2]?.init?.headers).toMatchObject({
      "If-Modified-Since": "Thu, 16 Jul 2026 12:00:00 GMT",
      "If-None-Match": '"openapi-1"'
    });
  });

  it.each([
    ["missing location", new Response(null, { status: 302 }), "omitted Location"],
    [
      "cross-origin redirect",
      new Response(null, { status: 302, headers: { location: "https://other.example/openapi" } }),
      "changed origin"
    ],
    [
      "transport downgrade",
      new Response(null, { status: 302, headers: { location: "http://localhost/openapi" } }),
      "downgraded transport"
    ]
  ])("rejects public-document %s", async (label, response, message) => {
    await expect(
      withFetch(
        () => Promise.resolve(response),
        () =>
          fetchAepPublicDocument({
            accept: "application/json",
            namespace: "openapi",
            parse: (value) => value,
            sameOriginRedirects: label !== "transport downgrade",
            url: "https://api.example.com/openapi.json"
          })
      )
    ).rejects.toThrow(message);
  });

  it("rejects redirect exhaustion, cacheless 304, HTTP failures, and unsafe URLs", async () => {
    const request = (url = "https://api.example.com/openapi.json") =>
      fetchAepPublicDocument({
        accept: "application/json",
        maxRedirects: 0,
        namespace: "openapi",
        parse: (value) => value,
        url
      });
    await expect(
      withFetch(
        () => Promise.resolve(new Response(null, { status: 302, headers: { location: "/next" } })),
        request
      )
    ).rejects.toThrow("redirect limit");
    await expect(
      withFetch(() => Promise.resolve(new Response(null, { status: 304 })), request)
    ).rejects.toThrow("without a cached representation");
    await expect(
      withFetch(() => Promise.resolve(new Response(null, { status: 503 })), request)
    ).rejects.toThrow("HTTP 503");
    await expect(request("https://user:secret@api.example.com/openapi.json")).rejects.toThrow(
      "must not contain user information"
    );
    await expect(request("http://api.example.com/openapi.json")).rejects.toThrow("require HTTPS");
  });

  it("bounds public-document completion time and streamed response bytes", async () => {
    const request = (options: { maxResponseBytes?: number; timeoutMs?: number } = {}) =>
      fetchAepPublicDocument({
        accept: "application/json",
        namespace: "openapi",
        parse: (value) => value,
        url: "https://api.example.com/openapi.json",
        ...options
      });
    const oversized = new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"value":'));
          controller.enqueue(new TextEncoder().encode("true}"));
          controller.close();
        }
      }),
      { headers: { "content-type": "application/json" } }
    );

    await expect(
      withFetch(
        () => Promise.resolve(oversized),
        () => request({ maxResponseBytes: 8 })
      )
    ).rejects.toThrow("too large");
    await expect(
      withFetch(
        (_input, init) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
              once: true
            });
          }),
        () => request({ timeoutMs: 1 })
      )
    ).rejects.toBeDefined();
    await expect(request({ timeoutMs: 0 })).rejects.toThrow("positive integer");
  });

  it("interprets inherited, public, and strict-slash OpenAPI policy", () => {
    const document = {
      openapi: "3.1.0",
      components: {
        securitySchemes: {
          session: { type: "http", scheme: "bearer", "x-aep-authentication-method": "oauth-bearer" }
        }
      },
      security: [{ session: [] }],
      paths: { "/items/{id}": { get: {} }, "/public": { get: { security: [] } } }
    };
    expect(
      interpretAepOpenApiOperation(document, {
        method: "get",
        trailingSlash: "strict",
        url: "https://api.example.com/items/1?x=1"
      })
    ).toMatchObject({
      state: "required",
      methods: ["oauth-bearer"],
      matchedOperation: { pathTemplate: "/items/{id}" }
    });
    expect(
      interpretAepOpenApiOperation(document, {
        trailingSlash: "strict",
        url: "https://api.example.com/public"
      }).state
    ).toBe("public");
    expect(
      interpretAepOpenApiOperation(document, {
        trailingSlash: "strict",
        url: "https://api.example.com/public/"
      })
    ).toMatchObject({ state: "fallback", strictSlashSuggestion: "/public" });
    expect(
      interpretAepOpenApiOperation(
        {
          ...document,
          paths: {
            "/v1/orders/{id}": { get: {} },
            "/v1/{kind}/123": { get: {} }
          }
        },
        { method: "get", trailingSlash: "strict", url: "https://api.example.com/v1/orders/123" }
      )
    ).toMatchObject({ matchedOperation: { pathTemplate: "/v1/orders/{id}" } });
  });

  it("handles invalid, missing, equivalent, ambiguous, and unusable OpenAPI policies", () => {
    const request = {
      method: "GET",
      trailingSlash: "equivalent" as const,
      url: "https://api.example.com/items/"
    };
    expect(() => interpretAepOpenApiOperation({ openapi: "3.0.3" }, request)).toThrow(
      "OpenAPI 3.1"
    );
    expect(interpretAepOpenApiOperation({ openapi: "3.1.0" }, request).state).toBe("fallback");
    expect(
      interpretAepOpenApiOperation(
        {
          openapi: "3.1.0",
          paths: {
            "/items": { get: { security: [{ first: [], second: [] }] } },
            "/{kind}": { get: {} }
          }
        },
        request
      )
    ).toMatchObject({ state: "fallback", matchedOperation: { pathTemplate: "/items" } });
    expect(
      interpretAepOpenApiOperation(
        {
          openapi: "3.1.0",
          paths: {
            "/{first}/items": { get: {} },
            "/items/{second}": { get: {} }
          }
        },
        { ...request, url: "https://api.example.com/items/items" }
      ).state
    ).toBe("fallback");
    expect(
      interpretAepOpenApiOperation(
        { openapi: "3.1.0", paths: { "/items": { get: { security: [{}] } } } },
        request
      ).state
    ).toBe("public");
  });

  it("classifies protected-resource responses and ignores malformed AEP challenges", async () => {
    const responses = [
      new Response("ok"),
      new Response(null, { status: 401, headers: { "www-authenticate": "Basic realm=x" } }),
      new Response(null, { status: 403 }),
      new Response(null, {
        status: 401,
        headers: {
          "www-authenticate":
            'AEP service_did="did:web:api.example.com", inspect="https://api.example.com/.well-known/aep", reason="expired"'
        }
      }),
      new Response(null, {
        status: 401,
        headers: {
          "www-authenticate": 'AEP service_did="did:web:api.example.com", inspect="not a valid URL"'
        }
      })
    ];
    const classifications = [];
    for (const response of responses) {
      classifications.push(
        await withFetch(
          () => Promise.resolve(response),
          () =>
            probeProtectedResource({
              body: "replayable",
              headers: { "X-Request": "test" },
              method: "POST",
              signal: new AbortController().signal,
              url: "https://api.example.com/items"
            })
        )
      );
    }
    expect(classifications.map((result) => result.classification)).toEqual([
      "success",
      "unrelated-authentication",
      "http-response",
      "aep-challenge",
      "unrelated-authentication"
    ]);
    expect(classifications[3]?.challenge).toMatchObject({ reason: "expired" });
  });

  it("uses the caller transport for each anonymous and authenticated request attempt", async () => {
    const calls: Array<{ headers: Headers; url: string }> = [];
    const transport: typeof globalThis.fetch = (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      calls.push({ headers: new Headers(init?.headers), url });
      if (calls.length === 1) {
        return Promise.resolve(
          new Response(null, {
            status: 401,
            headers: {
              "www-authenticate":
                'AEP service_did="did:web:api.example.com", inspect="https://api.example.com/.well-known/aep"'
            }
          })
        );
      }
      return Promise.resolve(new Response("ok"));
    };
    const agent = resourceAgent(
      resourceSession({
        authenticationHeaders: () => Promise.resolve({ "AEP-Authorization": "AEP credential" }),
        inspect: () =>
          Promise.resolve(
            inspectResult({
              ...minimalInspectDocument,
              authentication: { methods: ["oauth-bearer"] }
            })
          ),
        openApiPolicy: () =>
          Promise.resolve({
            freshness: "fetched",
            methods: [],
            source: "openapi",
            state: "fallback"
          })
      })
    );

    await expect(
      fetchProtectedResource({ agent, fetch: transport, url: "https://api.example.com/items" })
    ).resolves.toMatchObject({ status: 200 });
    expect(calls).toHaveLength(2);
    expect(calls[0]?.headers.has("AEP-Authorization")).toBe(false);
    expect(calls[1]?.headers.get("AEP-Authorization")).toBe("AEP credential");
  });

  it("validates protected-resource challenge origins and Service identities", async () => {
    const session = resourceSession();
    const agent = resourceAgent(session);
    const challenge = (serviceDid: string, inspect: string) =>
      new Response(null, {
        status: 401,
        headers: {
          "www-authenticate": `AEP service_did="${serviceDid}", inspect="${inspect}"`
        }
      });

    await expect(
      withFetch(
        () =>
          Promise.resolve(
            challenge("did:web:api.example.com", "https://other.example/.well-known/aep")
          ),
        () => fetchProtectedResource({ agent, url: "https://api.example.com/items" })
      )
    ).rejects.toMatchObject({ code: "invalid_redirect" });
    await expect(
      withFetch(
        () =>
          Promise.resolve(
            challenge("did:web:different.example", "https://api.example.com/.well-known/aep")
          ),
        () => fetchProtectedResource({ agent, url: "https://api.example.com/items" })
      )
    ).rejects.toMatchObject({ code: "validation_failed" });
  });

  it("rejects unusable OpenAPI authentication and conflicting presentation fields", async () => {
    const noMethods = resourceAgent(
      resourceSession({
        openApiPolicy: () =>
          Promise.resolve({
            freshness: "fetched",
            methods: [],
            source: "openapi",
            state: "required"
          })
      })
    );
    await expect(
      fetchProtectedResource({ agent: noMethods, url: "https://api.example.com/items" })
    ).rejects.toThrow("supplies no usable AEP method");

    const conflicting = resourceAgent(
      resourceSession({
        authenticationHeaders: () => Promise.resolve({ Authorization: "Bearer credential" }),
        openApiPolicy: () =>
          Promise.resolve({
            freshness: "fetched",
            methods: ["oauth-bearer"],
            source: "openapi",
            state: "required"
          })
      })
    );
    await expect(
      fetchProtectedResource({
        additionalAuthenticationHeaders: { Authorization: "Bearer caller" },
        agent: conflicting,
        url: "https://api.example.com/items"
      })
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("reports malformed and excessive protected-resource redirects", async () => {
    const agent = resourceAgent(resourceSession());
    await expect(
      withFetch(
        () => Promise.resolve(new Response(null, { status: 302 })),
        () => fetchProtectedResource({ agent, url: "https://api.example.com/items" })
      )
    ).rejects.toMatchObject({ code: "invalid_redirect" });
    await expect(
      withFetch(
        () => Promise.resolve(new Response(null, { status: 302, headers: { location: "/next" } })),
        () =>
          fetchProtectedResource({
            agent,
            maxRedirects: 0,
            url: "https://api.example.com/items"
          })
      )
    ).rejects.toMatchObject({ code: "invalid_redirect" });
  });

  it("restarts anonymously and strips authentication and payment fields across origins", async () => {
    const calls: Array<{ headers: Headers; url: string }> = [];
    const transport: typeof globalThis.fetch = (input, init) => {
      const url = new URL(
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url
      );
      const headers = new Headers(init?.headers);
      calls.push({ headers, url: url.href });
      if (!headers.has("AEP-Authorization")) {
        if (url.hostname === "other.example") {
          return Promise.resolve(new Response("ok"));
        }
        return Promise.resolve(
          new Response(null, {
            status: 401,
            headers: {
              "www-authenticate": `AEP service_did="did:web:${url.hostname}", inspect="${url.origin}/.well-known/aep"`
            }
          })
        );
      }
      if (url.hostname === "api.example.com") {
        return Promise.resolve(
          new Response(null, {
            status: 302,
            headers: { location: "https://other.example/items" }
          })
        );
      }
      return Promise.resolve(new Response("ok"));
    };
    const agent: AepAgent = {
      serviceSession: ({ serviceUrl }) => {
        const origin = new URL(serviceUrl).origin;
        const hostname = new URL(origin).hostname;
        return resourceSession({
          authenticationHeaders: () =>
            Promise.resolve({ "AEP-Authorization": `AEP ${hostname}-credential` }),
          inspect: () =>
            Promise.resolve(
              inspectResult({
                ...minimalInspectDocument,
                service: { did: `did:web:${hostname}` }
              })
            ),
          openApiPolicy: () =>
            Promise.resolve(
              hostname === "api.example.com"
                ? {
                    freshness: "fetched",
                    methods: ["aep-jwt"],
                    source: "openapi",
                    state: "required"
                  }
                : {
                    freshness: "fetched",
                    methods: [],
                    source: "openapi",
                    state: "fallback"
                  }
            )
        });
      }
    };

    const response = await fetchProtectedResource({
      additionalAuthenticationHeaders: { "X-API-Key": "service-secret" },
      agent,
      fetch: transport,
      headers: {
        Authorization: "Payment mpp-credential",
        "AEP-Authorization": "AEP stale-credential",
        "PAYMENT-SIGNATURE": "x402-signature"
      },
      url: "https://api.example.com/items"
    });

    expect(calls).toHaveLength(2);
    expect(response.status).toBe(200);
    expect(calls[1]?.url).toBe("https://other.example/items");
    expect(calls[1]?.headers.has("Authorization")).toBe(false);
    expect(calls[1]?.headers.has("AEP-Authorization")).toBe(false);
    expect(calls[1]?.headers.has("PAYMENT-SIGNATURE")).toBe(false);
    expect(calls[1]?.headers.has("X-API-Key")).toBe(false);
  });

  it("rejects Grant before identity recovery without signing or calling Grant", async () => {
    let signCalls = 0;
    const agent = createAepAgent({
      identityProvider: {
        getOrCreateIdentity: () => {
          throw new Error("must not provision");
        },
        signerFor: () => {
          signCalls += 1;
          return () => "jwt";
        }
      }
    });
    let grantCalls = 0;
    await withFetch(
      (input) => {
        const url = String(input);
        if (url.endsWith("/.well-known/aep"))
          return jsonResponsePromise({
            ...minimalInspectDocument,
            authentication: { methods: ["oauth-bearer"] }
          });
        if (url.endsWith("/aep/grant")) grantCalls += 1;
        return jsonResponsePromise({});
      },
      async () => {
        await expect(
          agent
            .serviceSession({ serviceUrl: "https://api.example.com" })
            .grant({ grantType: "oauth-bearer" })
        ).rejects.toMatchObject({ problem: { code: "not_recognized" } });
      }
    );
    expect(signCalls).toBe(0);
    expect(grantCalls).toBe(0);
  });
});

describe("@aep-foundation/agent Platform clients", () => {
  it("discovers Platform metadata", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const discovery = await withFetch(
      (input, init) => {
        calls.push(fetchCall(input, init));
        return jsonResponsePromise(minimalPlatformDiscoveryDocument);
      },
      () =>
        discoverPlatform({
          platformUrl: "https://platform.example.com/"
        })
    );

    expect(String(calls[0]?.input)).toBe("https://platform.example.com/.well-known/aep-platform");
    expect(calls[0]?.init?.headers).toEqual({
      Accept: "application/aep+json"
    });
    expect(String(discovery.endpointUrl("provision"))).toBe(
      "https://platform.example.com/v1/aep/agent-identities"
    );
  });

  it("rejects Platform discovery documents outside the complete wire contract", async () => {
    const discover = (document: unknown) =>
      withFetch(
        () => jsonResponsePromise(document),
        () => discoverPlatform({ platformUrl: "https://platform.example.com/" })
      );

    await expect(
      discover({ ...minimalPlatformDiscoveryDocument, aep_version: "2.0" })
    ).rejects.toThrow("unsupported AEP major version");
    await expect(
      discover({
        ...minimalPlatformDiscoveryDocument,
        endpoints: { ...minimalPlatformDiscoveryDocument.endpoints, sign: "v1/aep/sign" }
      })
    ).rejects.toThrow("must start with '/'");
    await expect(
      discover({
        ...minimalPlatformDiscoveryDocument,
        identity: { ...minimalPlatformDiscoveryDocument.identity, did_methods: [] }
      })
    ).rejects.toThrow("did_methods must not be empty");
    await expect(
      discover({
        ...minimalPlatformDiscoveryDocument,
        signing: {
          ...minimalPlatformDiscoveryDocument.signing,
          default_lifetime_seconds: "301"
        }
      })
    ).rejects.toThrow("default_lifetime_seconds is invalid");
  });

  it("provisions Platform-hosted did:web identities", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const discovery = await withFetch(
      () => jsonResponsePromise(minimalPlatformDiscoveryDocument),
      () =>
        discoverPlatform({
          platformUrl: "https://platform.example.com/"
        })
    );
    const result = await withFetch(
      (input, init) => {
        calls.push(fetchCall(input, init));
        return jsonResponsePromise(platformIdentityFixture());
      },
      () =>
        provisionPlatformIdentity({
          authorization: "Bearer demo-agent",
          discovery,
          idempotencyKey: "01J0AEPIDEMPOTENCY0000000001",
          platformUrl: "https://platform.example.com/",
          serviceDid: "did:web:api.service.example"
        })
    );

    expect(String(calls[0]?.input)).toBe("https://platform.example.com/v1/aep/agent-identities");
    expect(calls[0]?.init?.headers).toEqual({
      Accept: "application/aep+json",
      Authorization: "Bearer demo-agent",
      "Content-Type": "application/aep+json",
      "Idempotency-Key": "01J0AEPIDEMPOTENCY0000000001"
    });
    expect(JSON.parse(requestBody(calls[0]?.init?.body))).toEqual({
      service_did: "did:web:api.service.example"
    });
    expect(result.body.agent_did).toBe(
      "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001"
    );
  });

  it("creates delegated signers backed by the Platform sign endpoint", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const discovery = await withFetch(
      () => jsonResponsePromise(minimalPlatformDiscoveryDocument),
      () =>
        discoverPlatform({
          platformUrl: "https://platform.example.com/"
        })
    );
    const signer = createPlatformDelegatedSigner({
      authorization: "Bearer demo-agent",
      discovery,
      identity: platformIdentityFixture(),
      platformUrl: "https://platform.example.com/"
    });

    await expect(
      withFetch(
        (input, init) => {
          calls.push(fetchCall(input, init));
          return jsonResponsePromise({
            status: "completed",
            agent_did: platformIdentityFixture().agent_did,
            client_assertion: "signed.jwt",
            expires_at: "2026-07-06T12:05:00.000Z",
            issued_at: "2026-07-06T12:00:00.000Z",
            jti: "01J0AEPASSERTION0000000001",
            service_did: "did:web:api.service.example"
          });
        },
        () =>
          signer(
            buildClientAssertionClaims({
              agentDid: platformIdentityFixture().agent_did,
              clock: () => new Date("2026-07-06T12:00:00.000Z"),
              command: "enroll",
              jti: "01J0AEPASSERTION0000000001",
              serviceDid: "did:web:api.service.example",
              ttlSeconds: 300
            }),
            {
              command: "enroll",
              serviceDid: "did:web:api.service.example",
              signingAlgorithms: ["ES256"]
            }
          )
      )
    ).resolves.toMatchObject({ status: "completed", clientAssertion: "signed.jwt" });
    expect(String(calls[0]?.input)).toBe(
      "https://platform.example.com/v1/aep/agent-identities/pai_01J0AEPPLATFORM000000000001/sign"
    );
    expect(JSON.parse(requestBody(calls[0]?.init?.body))).toEqual({
      jti: "01J0AEPASSERTION0000000001",
      lifetime_seconds: "300",
      op: "enroll",
      service_did: "did:web:api.service.example"
    });
  });

  it("supports caller-defined authentication headers without exposing or overriding protocol headers", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const discovery = await withFetch(
      () => jsonResponsePromise(minimalPlatformDiscoveryDocument),
      () => discoverPlatform({ platformUrl: "https://platform.example.com/" })
    );
    const result = await withFetch(
      (input, init) => {
        calls.push(fetchCall(input, init));
        return jsonResponsePromise(platformIdentityFixture());
      },
      () =>
        provisionPlatformIdentity({
          authenticationHeaders: {
            Accept: "text/plain",
            "Content-Type": "text/plain",
            "Idempotency-Key": "caller-key",
            "X-CUSTOM-AUTH": "secret-api-key"
          },
          discovery,
          idempotencyKey: "sdk-key",
          platformUrl: "https://platform.example.com/",
          serviceDid: "did:web:api.service.example"
        })
    );

    expect(calls[0]?.init?.headers).toEqual({
      Accept: "application/aep+json",
      "Content-Type": "application/aep+json",
      "Idempotency-Key": "sdk-key",
      "X-CUSTOM-AUTH": "secret-api-key"
    });
    expect(result).not.toHaveProperty("authenticationHeaders");
    expect(result).not.toHaveProperty("headers");
  });

  it("resolves rotating authentication headers for every delegated Sign request", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    let token = 0;
    const discovery = await withFetch(
      () => jsonResponsePromise(minimalPlatformDiscoveryDocument),
      () => discoverPlatform({ platformUrl: "https://platform.example.com/" })
    );
    const signer = createPlatformDelegatedSigner({
      authenticationHeaders: () => Promise.resolve({ Authorization: `Bearer rotating-${++token}` }),
      discovery,
      identity: platformIdentityFixture(),
      platformUrl: "https://platform.example.com/"
    });
    const claims = buildClientAssertionClaims({
      agentDid: platformIdentityFixture().agent_did,
      clock: () => new Date("2026-07-06T12:00:00.000Z"),
      command: "enroll",
      jti: "01J0AEPASSERTION0000000001",
      serviceDid: "did:web:api.service.example",
      ttlSeconds: 300
    });
    await withFetch(
      (input, init) => {
        calls.push(fetchCall(input, init));
        return jsonResponsePromise({
          status: "completed",
          agent_did: platformIdentityFixture().agent_did,
          client_assertion: "signed.jwt",
          expires_at: "2026-07-06T12:05:00.000Z",
          issued_at: "2026-07-06T12:00:00.000Z",
          jti: claims.jti,
          service_did: claims.aud
        });
      },
      async () => {
        await signer(claims, {
          command: "enroll",
          serviceDid: claims.aud,
          signingAlgorithms: ["ES256"]
        });
        await signer(claims, {
          command: "enroll",
          serviceDid: claims.aud,
          signingAlgorithms: ["ES256"]
        });
      }
    );
    expect(calls[0]?.init?.headers).toMatchObject({ Authorization: "Bearer rotating-1" });
    expect(calls[1]?.init?.headers).toMatchObject({ Authorization: "Bearer rotating-2" });
  });

  it("creates a single Platform-backed Agent identity provider", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const provider = createPlatformIdentityProvider({
      authorization: "Bearer demo-agent",
      idempotencyKey: "01J0AEPIDEMPOTENCY0000000001",
      platformUrl: "https://platform.example.com/"
    });
    const identity = await withFetch(
      (input, init) => {
        calls.push(fetchCall(input, init));

        if (String(input).endsWith("/.well-known/aep-platform")) {
          return jsonResponsePromise(minimalPlatformDiscoveryDocument);
        }

        if (String(input).includes("?")) {
          return jsonResponsePromise({ count: "0", data: [], total: "0" });
        }

        return jsonResponsePromise(platformIdentityFixture());
      },
      () =>
        provider.getOrCreateIdentity({
          inspect: minimalInspectDocument,
          serviceDid: "did:web:api.service.example",
          serviceUrl: "https://api.service.example/"
        })
    );

    expect(identity).toMatchObject({
      agentDid: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
      identityKind: "platform-hosted",
      serviceDid: "did:web:api.service.example"
    });
    expect(calls.map((call) => String(call.input))).toEqual([
      "https://platform.example.com/.well-known/aep-platform",
      "https://platform.example.com/v1/aep/agent-identities?descending=true&limit=100&service_did=did%3Aweb%3Aapi.service.example",
      "https://platform.example.com/v1/aep/agent-identities"
    ]);
  });

  it("recovers a Platform-backed identity by Service DID", async () => {
    const calls: Array<{ input: URL | string; init?: RequestInit }> = [];
    const provider = createPlatformIdentityProvider({
      authorization: "Bearer demo-agent",
      platformUrl: "https://platform.example.com/"
    });
    const identity = await withFetch(
      (input, init) => {
        calls.push(fetchCall(input, init));
        if (String(input).endsWith("/.well-known/aep-platform"))
          return jsonResponsePromise(minimalPlatformDiscoveryDocument);
        return jsonResponsePromise({ count: 1, data: [platformIdentityFixture()], total: 1 });
      },
      () =>
        provider.getOrCreateIdentity({
          inspect: minimalInspectDocument,
          serviceDid: "did:web:api.service.example",
          serviceUrl: "https://api.service.example/"
        })
    );

    expect(identity).toMatchObject({
      agentDid: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
      serviceDid: "did:web:api.service.example"
    });
    expect(String(calls[1]?.input)).toBe(
      "https://platform.example.com/v1/aep/agent-identities?descending=true&limit=100&service_did=did%3Aweb%3Aapi.service.example"
    );
  });
});

describe("@aep-foundation/agent credential helpers", () => {
  it("selects compatible grant types from Inspect metadata", () => {
    expect(
      selectGrantType(inspectResult(), {
        preferredGrantTypes: ["custom-token", "api-key"]
      })
    ).toBe("api-key");

    expect(() =>
      selectGrantType(inspectResult(), {
        preferredGrantTypes: ["custom-token"]
      })
    ).toThrow("compatible grant type");
  });

  it("stores issued credentials and creates presentation headers", async () => {
    const store = createInMemorySessionCredentialStore();
    const grant = {
      body: {
        access_token: "access-token",
        credential_id: "cred_123",
        expires_at: "2999-05-28T12:00:00Z",
        scopes: ["read"],
        token_type: "Bearer" as const
      },
      commandUrl: new URL("https://api.example.com/aep/grant"),
      status: 200
    };
    const record = sessionCredentialRecordFromGrantResult(grant, {
      clock: () => new Date("2026-05-28T11:00:00.000Z"),
      grantType: "oauth-bearer",
      inspect: inspectResult(),
      serviceUrl: "https://api.example.com"
    });

    await store.saveCredential(record);

    expect(await store.findCredential("did:web:api.example.com", "cred_123")).toMatchObject({
      credentialId: "cred_123",
      expiresAt: "2999-05-28T12:00:00Z",
      grantType: "oauth-bearer",
      issuedAt: "2026-05-28T11:00:00.000Z",
      serviceDid: "did:web:api.example.com"
    });
    expect(credentialPresentationHeaders(grant.body)).toEqual({
      Authorization: "Bearer access-token"
    });
    expect(credentialPresentationHeaders(grant.body, "dedicated")).toEqual({
      "AEP-Authorization": "Bearer access-token"
    });
    expect(
      credentialPresentationHeaders({
        api_key: "api-key",
        credential_id: "key_123",
        expires_at: "2026-05-28T12:00:00Z",
        header: "X-API-Key",
        scopes: []
      })
    ).toEqual({
      "X-API-Key": "api-key"
    });
    expect(
      credentialPresentationHeaders({
        credential_id: "basic_123",
        expires_at: "2026-05-28T12:00:00Z",
        password: "password",
        scopes: [],
        username: "user"
      })
    ).toEqual({
      Authorization: "Basic dXNlcjpwYXNzd29yZA=="
    });

    await store.deleteCredential("did:web:api.example.com", "cred_123");
    expect(await store.listCredentials("did:web:api.example.com")).toEqual([]);
  });

  it("creates protected-resource authentication headers from JWT assertions or credentials", async () => {
    const jwtHeaders = await clientAssertionAuthenticationHeaders({
      agentDid: "did:web:agent.example.com:agents:123",
      inspect: inspectResult(),
      jti: "protected-resource-jti",
      signer: (claims, context) =>
        JSON.stringify({
          algs: context.signingAlgorithms,
          aud: claims.aud,
          jti: claims.jti,
          op: claims.op
        })
    });

    expect(jwtHeaders).toEqual({
      Authorization: `AEP ${JSON.stringify({
        algs: ["EdDSA", "ES256"],
        aud: "did:web:api.example.com",
        jti: "protected-resource-jti",
        op: "status"
      })}`
    });

    await expect(
      clientAssertionAuthenticationHeaders({
        agentDid: "did:web:agent.example.com:agents:123",
        allowInsecureLoopback: true,
        inspect: inspectResult(),
        jti: "loopback-resource-jti",
        resource: "http://127.0.0.1:3000/api/resource",
        signer: (claims) => claims.resource ?? "missing"
      })
    ).resolves.toEqual({
      Authorization: "AEP http://127.0.0.1:3000/api/resource"
    });

    await expect(
      clientAssertionAuthenticationHeaders({
        agentDid: "did:web:agent.example.com:agents:123",
        carrier: "dedicated",
        inspect: inspectResult(),
        jti: "dedicated-jti",
        signer: () => "signed"
      })
    ).resolves.toEqual({ "AEP-Authorization": "AEP signed" });

    await expect(
      protectedResourceAuthenticationHeaders({
        credential: {
          access_token: "access-token",
          credential_id: "cred_123",
          expires_at: "2026-05-28T12:00:00Z",
          scopes: ["read"],
          token_type: "Bearer"
        }
      })
    ).resolves.toEqual({
      Authorization: "Bearer access-token"
    });
  });
});

function jsonResponse(
  body: unknown,
  options: {
    ok?: boolean;
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
  } = {}
): ResponseLike {
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    headers: headerMap({ "content-type": "application/aep+json", ...(options.headers ?? {}) }),
    json: () => Promise.resolve(body),
    ...(options.statusText === undefined ? {} : { statusText: options.statusText })
  };
}

function fetchJsonResponse(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { headers: { "content-type": AEP_MEDIA_TYPE } })
  );
}

function sessionCredentialRecord(
  credentialId: string,
  grantType: "api-key" | "oauth-bearer"
): AepSessionCredentialRecord {
  const expiresAt = "2999-05-28T12:00:00Z";
  const credential =
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
          token_type: "Bearer" as const
        };
  return {
    credential,
    credentialId,
    expiresAt,
    grantType,
    issuedAt: "2026-05-28T12:00:00Z",
    serviceDid: "did:web:api.example.com",
    serviceUrl: "https://api.example.com"
  };
}

function resourceSession(overrides: Partial<AepServiceSession> = {}): AepServiceSession {
  const unavailable = () => Promise.reject(new Error("not used by this test"));
  return {
    authenticationHeaders: unavailable,
    enroll: unavailable,
    forgetCredential: unavailable,
    grant: unavailable,
    identity: unavailable,
    inspect: () => Promise.resolve(inspectResult()),
    openApiPolicy: () =>
      Promise.resolve({ freshness: "fetched", methods: [], source: "openapi", state: "fallback" }),
    revoke: unavailable,
    status: unavailable,
    ...overrides
  };
}

function resourceAgent(session: AepServiceSession): AepAgent {
  return { serviceSession: () => session };
}

function jsonResponsePromise(
  body: unknown,
  options?: {
    ok?: boolean;
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
  }
): Promise<ResponseLike> {
  return Promise.resolve(jsonResponse(body, options));
}

async function withFetch<T>(
  fetchImpl: (input: URL | string, init?: RequestInit) => Promise<ResponseLike>,
  callback: () => T | Promise<T>
): Promise<T> {
  const previousFetch = globalThis.fetch;

  try {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: fetchImpl
    });

    return await Promise.resolve(callback());
  } finally {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: previousFetch
    });
  }
}

function fetchCall(
  input: URL | string,
  init?: RequestInit
): { input: URL | string; init?: RequestInit } {
  return {
    input,
    ...(init === undefined ? {} : { init })
  };
}

function requestBody(body: RequestInit["body"] | undefined): string {
  if (typeof body !== "string") {
    throw new TypeError("Expected a string request body.");
  }

  return body;
}

function headerMap(headers: Record<string, string>) {
  const normalized = Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])
  );

  return {
    get: (name: string) => normalized[name.toLowerCase()] ?? null
  };
}

function inspectResult(document: InspectDocument = minimalInspectDocument): InspectServiceResult {
  return {
    document,
    inspectUrl: new URL("https://api.example.com/.well-known/aep"),
    commandUrl: (command) => new URL(`/aep/${command}`, "https://api.example.com")
  };
}

function platformIdentityFixture(): PlatformAgentIdentity {
  return {
    agent_did: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
    agent_identity_id: "pai_01J0AEPPLATFORM000000000001",
    created_at: "2026-07-06T12:00:00.000Z",
    did_document_url: "https://platform.example.com/agents/01J0AEPPLATFORM000000000001/did.json",
    key_id: "did:web:platform.example.com:agents:01J0AEPPLATFORM000000000001",
    service_did: "did:web:api.service.example",
    signing_algorithms: ["ES256"],
    status: "active",
    updated_at: "2026-07-06T12:00:00.000Z"
  };
}
