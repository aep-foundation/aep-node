import { generateKeyPairSync } from "node:crypto";

import { verifyClientAssertionJwt } from "@aep-foundation/core";
import type { InspectDocument } from "@aep-foundation/core";
import { describe, expect, it } from "vitest";

import {
  buildClientAssertionClaims,
  clientAssertionAuthenticationHeaders,
  createInMemorySessionCredentialStore,
  createAepAgent,
  createPlatformIdentityProvider,
  createJwtClientAssertionSigner,
  createPlatformDelegatedSigner,
  credentialPresentationHeaders,
  discoverPlatform,
  enrollService,
  grantService,
  inspectService,
  provisionPlatformIdentity,
  revokeService,
  resolveServiceReference,
  selectGrantType,
  sessionCredentialRecordFromGrantResult,
  signClientAssertion,
  AepPendingSignError,
  protectedResourceAuthenticationHeaders,
  statusService
} from "../src/index.js";
import type {
  AepClientAssertionSigner,
  AepInspectError,
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

    await expect(
      signClientAssertion({
        agentDid: "did:web:agent.example.com:agents:123",
        clock: () => new Date("2026-05-28T12:00:00.000Z"),
        command: "status",
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
      kid: "agent-key-1"
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
    const signer: AepClientAssertionSigner = (claims) => {
      signerEvents.push(claims.op);
      return `jwt.${claims.op}.${claims.jti}`;
    };
    const agent = createAepAgent({
      assertionClock: () => new Date("2026-05-28T12:00:00.000Z"),
      assertionJti: () => `jti-${signerEvents.length + 1}`,
      identityProvider: {
        getOrCreateIdentity: () => ({
          agentDid: "did:web:agent.example.com:agents:123",
          identityKind: "sovereign",
          serviceDid: "did:web:api.example.com",
          signingAlgorithms: ["ES256"]
        }),
        signerFor: () => signer
      }
    });
    const session = agent.serviceSession({
      serviceUrl: "https://api.example.com"
    });
    const fetch = (input: URL | string) =>
      jsonResponsePromise(
        String(input).endsWith("/.well-known/aep")
          ? minimalInspectDocument
          : String(input).endsWith("/grant")
            ? {
                access_token: "access-token",
                credential_id: "cred_123",
                expires_at: "2026-05-28T12:00:00Z",
                scopes: [],
                token_type: "Bearer"
              }
            : String(input).endsWith("/revoke")
              ? {}
              : String(input).endsWith("/status")
                ? {
                    owner_action_required: "false",
                    since: "2026-05-28T12:00:00Z",
                    status: "active"
                  }
                : {
                    status: "active"
                  }
      );

    await withFetch(fetch, async () => {
      await expect(
        session.enroll({
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
          idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-agentrevoke"
        })
      ).resolves.toMatchObject({
        body: {}
      });
    });
    expect(signerEvents).toEqual(["enroll", "status", "grant", "revoke"]);
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
      "https://platform.example.com/v1/aep/agent-identities"
    ]);
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
        expires_at: "2026-05-28T12:00:00Z",
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
      expiresAt: "2026-05-28T12:00:00Z",
      grantType: "oauth-bearer",
      issuedAt: "2026-05-28T11:00:00.000Z",
      serviceDid: "did:web:api.example.com"
    });
    expect(credentialPresentationHeaders(grant.body)).toEqual({
      Authorization: "Bearer access-token"
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
