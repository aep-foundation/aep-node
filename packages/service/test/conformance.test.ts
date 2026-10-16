import { generateKeyPairSync } from "node:crypto";
import { storedCredentialFixture } from "./credential-fixture.js";

import { describe, expect, it } from "vitest";

import { signClientAssertionJwt } from "@aep-foundation/core";
import type { AepClientAssertionClaims } from "@aep-foundation/core";

import {
  DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS,
  basicGrantType,
  buildInspectDocument,
  clientAssertionFromAepAuthorization,
  createAepService,
  createDidWebClientAssertionVerifier,
  createHostedPlatformClientAssertionVerifier,
  createInMemoryClientAssertionReplayStore,
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
  storedApiKeyGrantType,
  storedBasicGrantType,
  storedOAuthBearerGrantType
} from "../src/index.js";
import type {
  AepServiceCredentialRecord,
  AepServiceOptions,
  AepServiceCredentialStore
} from "../src/index.js";

const SERVICE_DID = "did:web:api.example.com";
const AGENT_DID = "did:web:agent.example.com:agents:123";
const RESOURCE = "https://api.example.com/orders";
const NOW = new Date("2026-05-28T12:00:00.000Z");
const FUTURE = "2999-05-28T12:00:00.000Z";

function serviceOptions(overrides: Partial<AepServiceOptions> = {}): AepServiceOptions {
  return {
    authenticationMethods: ["aep-jwt"],
    identityMethods: [didWebIdentityMethod()],
    serviceDid: SERVICE_DID,
    ...overrides
  };
}

function claims(overrides: Partial<AepClientAssertionClaims> = {}): AepClientAssertionClaims {
  const iat = Math.floor(NOW.getTime() / 1000);

  return {
    aud: SERVICE_DID,
    exp: iat + 300,
    iat,
    iss: AGENT_DID,
    jti: "jti-1",
    op: "enroll",
    sub: AGENT_DID,
    ...overrides
  };
}

/**
 * A verifier that trusts a base64url-encoded claim set, so tests can exercise the engine's own
 * checks without signing. The encoding matters: a credential carried in `AEP-Authorization` may
 * not contain a comma, which raw JSON would.
 */
function jsonVerifier() {
  return (assertion: string) =>
    JSON.parse(Buffer.from(assertion, "base64url").toString("utf8")) as AepClientAssertionClaims;
}

function encoded(payload: AepClientAssertionClaims): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function apiKeyRecord(
  agentDid: string,
  credentialId: string,
  apiKey: string,
  header: string,
  scopes: string[] = []
): AepServiceCredentialRecord {
  return {
    agentDid,
    createdAt: "2026-05-28T12:00:00.000Z",
    credential: storedCredentialFixture({
      api_key: apiKey,
      credential_id: credentialId,
      expires_at: FUTURE,
      header,
      scopes
    }),
    credentialId,
    expiresAt: FUTURE,
    grantType: "api-key"
  };
}

describe("signed assertion authentication boundaries", () => {
  it("does not widen Inspect algorithms through verifier configuration", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const service = createAepService(
      serviceOptions({
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: createJwtClientAssertionVerifier({
          algorithms: ["ES384"],
          key: publicKey,
          currentDate: NOW
        })
      })
    );
    const assertion = await signClientAssertionJwt(claims(), { alg: "ES384", key: privateKey });
    expect(
      (
        await service.enroll(
          { agent_did: AGENT_DID },
          {
            clientAssertion: assertion,
            idempotencyKey: "algorithm"
          }
        )
      ).status
    ).toBe(401);
  });

  it("keeps protected-resource methods consistent with Inspect after caller mutation", async () => {
    const methods = ["aep-jwt"];
    const service = createAepService(
      serviceOptions({
        authenticationMethods: methods,
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier()
      })
    );
    methods.splice(0, 1, "oauth-bearer");
    expect(service.inspectDocument().authentication?.methods).toEqual(["aep-jwt"]);
    await expect(
      service.authenticateProtectedResource({
        method: "GET",
        url: RESOURCE,
        headers: {
          Authorization: `AEP ${encoded(claims({ op: "authenticate", resource: RESOURCE }))}`
        }
      })
    ).resolves.toMatchObject({ authenticated: true });
    await expect(
      service.authenticateProtectedResource({
        method: "GET",
        url: RESOURCE,
        headers: { Authorization: "Bearer token" }
      })
    ).resolves.toMatchObject({
      authenticated: false,
      response: {
        body: { code: "unsupported_authentication_method" }
      }
    });
  });

  it.each([undefined, "https://api.example.com/custom-inspect"])(
    "includes discovery parameters on failed assertions with inspect %s",
    async (inspectUrl) => {
      const service = createAepService(
        serviceOptions({
          ...(inspectUrl === undefined ? {} : { inspectUrl }),
          clientAssertionVerifier: jsonVerifier()
        })
      );
      const result = await service.authenticateProtectedResource({
        method: "GET",
        url: RESOURCE,
        headers: { Authorization: "AEP invalid" }
      });
      if (result.authenticated) throw new Error("Expected authentication failure.");
      expect(result.response.headers?.["WWW-Authenticate"]).toBe(
        `AEP service_did="${SERVICE_DID}", inspect="${inspectUrl ?? "https://api.example.com/.well-known/aep"}", reason="not_recognized"`
      );
    }
  );

  it.each(["Bearer token", "basic dTpw"])(
    "distinguishes an unsupported method from invalid credentials: %s",
    async (authorization) => {
      const service = createAepService(serviceOptions());
      await expect(
        service.authenticateProtectedResource({
          method: "GET",
          url: RESOURCE,
          headers: { Authorization: authorization }
        })
      ).resolves.toMatchObject({
        authenticated: false,
        response: {
          body: { code: "unsupported_authentication_method" }
        }
      });
      const supported = createAepService(
        serviceOptions({ authenticationMethods: ["oauth-bearer", "basic"] })
      );
      await expect(
        supported.authenticateProtectedResource({
          method: "GET",
          url: RESOURCE,
          headers: { Authorization: authorization }
        })
      ).resolves.toMatchObject({
        authenticated: false,
        response: {
          body: { code: "not_recognized" }
        }
      });
    }
  );

  it.each(["aep abc.def.ghi", "AeP   abc.def.ghi"])("extracts %s", (header) => {
    expect(clientAssertionFromAepAuthorization(header)).toBe("abc.def.ghi");
  });
  it.each([AGENT_DID, "did:key:z6Mktest"])(
    "enforces advertised identity methods for %s",
    async (agentDid) => {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const service = createAepService(
        serviceOptions({
          clientAssertion: { clock: () => NOW },
          clientAssertionVerifier: createJwtClientAssertionVerifier({
            key: publicKey,
            currentDate: NOW
          })
        })
      );
      for (const op of ["enroll", "authenticate"] as const) {
        const token = await signClientAssertionJwt(
          claims({
            iss: agentDid,
            sub: agentDid,
            op,
            jti: op,
            ...(op === "authenticate" ? { resource: RESOURCE } : {})
          }),
          { alg: "EdDSA", key: privateKey }
        );
        if (op === "enroll") {
          const result = await service.enroll(
            { agent_did: agentDid },
            { clientAssertion: token, idempotencyKey: "method-check" }
          );
          expect(result.status).toBe(agentDid === AGENT_DID ? 200 : 401);
        } else {
          const result = await service.authenticateProtectedResource({
            method: "GET",
            url: RESOURCE,
            headers: { Authorization: `AEP ${token}` }
          });
          expect(result.authenticated).toBe(agentDid === AGENT_DID);
        }
      }
    }
  );

  it.each(["Authorization", "AEP-Authorization"])(
    "accepts multiple spaces in %s",
    async (header) => {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const service = createAepService(
        serviceOptions({
          clientAssertion: { clock: () => NOW },
          clientAssertionVerifier: createJwtClientAssertionVerifier({
            key: publicKey,
            currentDate: NOW
          })
        })
      );
      const token = await signClientAssertionJwt(
        claims({ op: "authenticate", resource: RESOURCE }),
        { alg: "EdDSA", key: privateKey }
      );
      await expect(
        service.authenticateProtectedResource({
          method: "GET",
          url: RESOURCE,
          headers: { [header]: `aEp   ${token}` }
        })
      ).resolves.toMatchObject({ authenticated: true });
    }
  );
});

describe("stored credential verifiers", () => {
  it.each([undefined, ["X-API-Key"], ["x-other"], []])(
    "validates issued headers against advertised names %j before persistence",
    async (headerNames) => {
      const store = createInMemoryServiceCredentialStore();
      const definition = storedApiKeyGrantType({
        store,
        config: headerNames === undefined ? {} : { header_names: headerNames },
        issue: () => ({
          api_key: "test-secret",
          credential_id: "header-check",
          expires_at: FUTURE,
          header: "x-api-key",
          scopes: []
        })
      });
      const service = createAepService(
        serviceOptions({
          grantTypes: [definition],
          clientAssertion: { clock: () => NOW },
          clientAssertionVerifier: jsonVerifier()
        })
      );
      await service.enroll(
        { agent_did: AGENT_DID },
        {
          clientAssertion: encoded(claims()),
          idempotencyKey: "enroll"
        }
      );
      const result = service.grant(
        { grant_type: "api-key" },
        {
          clientAssertion: encoded(claims({ op: "grant", jti: "grant" })),
          idempotencyKey: "grant"
        }
      );
      if (headerNames === undefined || headerNames.includes("X-API-Key")) {
        await expect(result).resolves.toMatchObject({ status: 200 });
        expect(await store.listCredentials()).toHaveLength(1);
      } else {
        await expect(result).rejects.toThrow(/advertised header_names/u);
        expect(await store.listCredentials()).toHaveLength(0);
      }
    }
  );
  it.each([
    { salt: "invalid", digest: "a".repeat(64) },
    { salt: "a".repeat(32), digest: "invalid" }
  ])("rejects an invalid persisted verifier: %j", (verifier) => {
    const record = apiKeyRecord(AGENT_DID, "invalid-verifier", "key", "X-API-Key");
    record.credential.verifier = verifier;
    expect(() => createInMemoryServiceCredentialStore([record])).toThrow(
      "Invalid stored AEP credential verifier or metadata."
    );
  });

  it.each(["basic", "oauth-bearer"] as const)(
    "issues and verifies %s without persisting its secret",
    async (grantTypeName) => {
      const store = createInMemoryServiceCredentialStore();
      const metadata = { credential_id: "hashed-session", expires_at: FUTURE, scopes: ["read"] };
      const definition =
        grantTypeName === "basic"
          ? storedBasicGrantType({
              store,
              issue: () => ({
                ...metadata,
                username: "agent",
                password: "secret-password",
                api_key: "unrelated-extension",
                header: "X-Unrelated"
              })
            })
          : storedOAuthBearerGrantType({
              store,
              issue: () => ({
                ...metadata,
                token_type: "Bearer",
                access_token: "secret-token",
                api_key: "unrelated-extension",
                header: "X-Unrelated"
              })
            });
      const handler = definition.handler;
      if (handler?.authenticate === undefined) throw new Error("Missing credential handler");
      const context = {
        agentDid: AGENT_DID,
        enrollment: undefined as never,
        grantType: grantTypeName
      };
      const result = await handler.grant({ grant_type: grantTypeName }, context);
      expect(result).toMatchObject(
        grantTypeName === "basic"
          ? { password: "secret-password" }
          : { access_token: "secret-token" }
      );
      const [record] = await store.listCredentials();
      expect(JSON.stringify(record)).not.toContain("secret-password");
      expect(JSON.stringify(record)).not.toContain("secret-token");
      expect(JSON.stringify(record)).not.toContain("unrelated-extension");
      const authorization =
        grantTypeName === "basic"
          ? `Basic ${Buffer.from("agent:secret-password").toString("base64")}`
          : "Bearer secret-token";
      await expect(
        handler.authenticate({ now: NOW, headers: { authorization } })
      ).resolves.toMatchObject({ agentDid: AGENT_DID, scopes: ["read"] });
      const wrong =
        grantTypeName === "basic"
          ? `Basic ${Buffer.from("agent:wrong").toString("base64")}`
          : "Bearer wrong";
      await expect(
        handler.authenticate({ now: NOW, headers: { authorization: wrong } })
      ).resolves.toBeUndefined();
      await expect(
        handler.authenticate({
          now: NOW,
          headers: {
            authorization:
              grantTypeName === "basic" ? "Bearer secret-password" : "Basic c2VjcmV0LXRva2Vu"
          }
        })
      ).resolves.toBeUndefined();
      await expect(
        handler.authenticate({ now: NOW, headers: { "x-unrelated": "unrelated-extension" } })
      ).resolves.toBeUndefined();
      await handler.revoke(
        { credential_id: metadata.credential_id, grant_type: grantTypeName },
        context
      );
      await expect(
        handler.authenticate({ now: NOW, headers: { authorization } })
      ).resolves.toBeUndefined();
    }
  );

  it("persists a salted verifier without raw secrets or arbitrary issuer fields", async () => {
    const store = createInMemoryServiceCredentialStore();
    const issued = {
      api_key: "private-api-key",
      credential_id: "hashed-1",
      expires_at: FUTURE,
      scopes: ["read"],
      header: "X-API-Key",
      private_extension: "must-not-persist"
    };
    const definition = storedApiKeyGrantType({ store, issue: () => issued });
    const context = { agentDid: AGENT_DID, enrollment: undefined as never, grantType: "api-key" };
    const result = await definition.handler?.grant({ grant_type: "api-key" }, context);
    expect(result).toEqual(issued);
    const [record] = await store.listCredentials();
    expect(record?.credential).toMatchObject({
      header: "X-API-Key",
      scopes: ["read"]
    });
    expect(record?.credential.verifier.salt).toMatch(/^[a-f0-9]{32}$/u);
    expect(record?.credential.verifier.digest).toMatch(/^[a-f0-9]{64}$/u);
    expect(JSON.stringify(record)).not.toContain(issued.api_key);
    expect(JSON.stringify(record)).not.toContain(issued.private_extension);
    await expect(
      definition.handler?.authenticate?.({ now: NOW, headers: { "x-api-key": issued.api_key } })
    ).resolves.toMatchObject({ agentDid: AGENT_DID });
    await expect(
      definition.handler?.authenticate?.({ now: NOW, headers: { "x-api-key": "wrong-key" } })
    ).resolves.toBeUndefined();
    issued.credential_id = "hashed-2";
    await definition.handler?.grant({ grant_type: "api-key" }, context);
    const records = await store.listCredentials();
    expect(records[0]?.credential.verifier.salt).not.toBe(records[1]?.credential.verifier.salt);
    expect(records[0]?.credential.verifier.digest).not.toBe(records[1]?.credential.verifier.digest);
  });
});

describe("the WWW-Authenticate challenge cannot be injected", () => {
  const hostile = [
    'did:web:api.example.com", evil="1',
    "did:web:api.example.com\\",
    "did:web:api.example.com\r\nX-Injected: 1",
    "did:web:api.example.com\u0000"
  ];

  it.each(hostile)("refuses a service DID carrying %j at construction", (serviceDid) => {
    expect(() => createAepService(serviceOptions({ serviceDid }))).toThrow(
      /quote, a backslash, or a control character/u
    );
  });

  it("refuses an Inspect URL that would break out of the quoted string", () => {
    expect(() =>
      createAepService(
        serviceOptions({ inspectUrl: 'https://api.example.com/.well-known/aep", evil="1' })
      )
    ).toThrow(/quote, a backslash, or a control character/u);
  });

  it("emits a well-formed challenge for ordinary configuration", async () => {
    const service = createAepService(serviceOptions());
    const result = await service.authenticateProtectedResource({
      headers: {},
      method: "GET",
      url: RESOURCE
    });

    expect(result.authenticated).toBe(false);
    expect(isActiveProtectedResourceAuthentication(result)).toBe(false);

    if (result.authenticated) throw new Error("unreachable");

    expect(result.response.headers?.["WWW-Authenticate"]).toBe(
      `AEP service_did="${SERVICE_DID}", inspect="https://api.example.com/.well-known/aep", reason="authentication_required"`
    );
    expect(result.response.status).toBe(401);
    expect(result.response.body.code).toBe("authentication_required");
  });

  it("uses a configured Inspect URL in the challenge", async () => {
    const service = createAepService(
      serviceOptions({ inspectUrl: "https://api.example.com/aep/inspect" })
    );
    const result = await service.authenticateProtectedResource({
      headers: {},
      method: "GET",
      url: RESOURCE
    });

    if (result.authenticated) throw new Error("unreachable");

    expect(result.response.headers?.["WWW-Authenticate"]).toContain(
      'inspect="https://api.example.com/aep/inspect"'
    );
  });
});

describe("a protected-resource URL must be absolute", () => {
  it("reports a relative URL as a caller error rather than a bare Invalid URL", async () => {
    const service = createAepService(serviceOptions());

    await expect(
      service.authenticateProtectedResource({ headers: {}, method: "GET", url: "/orders" })
    ).rejects.toThrow(/must be absolute/u);
  });

  it("accepts a URL instance", async () => {
    const service = createAepService(serviceOptions());
    const result = await service.authenticateProtectedResource({
      headers: {},
      method: "GET",
      url: new URL(RESOURCE)
    });

    expect(result.authenticated).toBe(false);
  });
});

describe("hosted Platform verification covers protected-resource assertions", () => {
  it.each([
    "http://platform.example/v",
    "https://user:secret@platform.example/v",
    "https://platform.example/v#fragment"
  ])("rejects unsafe verification endpoint %s", (endpoint) => {
    expect(() => createHostedPlatformClientAssertionVerifier({ endpoint })).toThrow(
      /HTTPS endpoint/u
    );
  });
  it.each([0, -1, 1.5, NaN, Infinity])("rejects timeout %s", (timeoutMs) => {
    expect(() =>
      createHostedPlatformClientAssertionVerifier({
        endpoint: "https://platform.example/v",
        timeoutMs
      })
    ).toThrow(/positive integer/u);
  });
  it("bounds verification and disallows redirects", async () => {
    const verifier = createHostedPlatformClientAssertionVerifier({
      endpoint: "https://platform.example/v",
      timeoutMs: 10,
      fetch: (_url, init) => {
        expect(init?.redirect).toBe("error");
        const signal = init?.signal;
        if (!signal) throw new Error("Expected abort signal.");
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () =>
            new Promise((_resolve, reject) => {
              signal.addEventListener("abort", () => reject(new Error("Verification timeout")), {
                once: true
              });
            })
        });
      }
    });
    await expect(
      verifier(assertion, {
        clientAssertion: assertion,
        command: "authenticate",
        resource: RESOURCE,
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      })
    ).rejects.toThrow(/timeout/iu);
  });
  function hostedVerifier(body: Record<string, unknown>, status = 200) {
    return createHostedPlatformClientAssertionVerifier({
      authorization: "Bearer platform-token",
      endpoint: "https://platform.example/v1/aep/verifications",
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify(body), {
            headers: { "content-type": "application/json" },
            status
          })
        )
    });
  }

  const assertion = [
    Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" }), "utf8").toString("base64url"),
    encoded(claims({ op: "authenticate", resource: RESOURCE })),
    "signature"
  ].join(".");

  it("accepts a verified authenticate assertion", async () => {
    const verifier = hostedVerifier({
      agent_did: AGENT_DID,
      op: "authenticate",
      reason: "verified",
      service_did: SERVICE_DID,
      verified: true
    });

    await expect(
      verifier(assertion, {
        clientAssertion: assertion,
        command: "authenticate",
        resource: RESOURCE,
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      })
    ).resolves.toMatchObject({ op: "authenticate", resource: RESOURCE });
  });

  it("rejects a response that does not confirm the assertion", async () => {
    const context = {
      clientAssertion: assertion,
      command: "authenticate" as const,
      resource: RESOURCE,
      serviceDid: SERVICE_DID,
      signingAlgorithms: ["EdDSA" as const]
    };

    const unverified = hostedVerifier({
      agent_did: AGENT_DID,
      op: "authenticate",
      reason: "not_recognized",
      service_did: SERVICE_DID,
      verified: false
    });
    await expect(verifier(unverified, context)).rejects.toThrow(/did not recognize/u);

    const wrongAgent = hostedVerifier({
      agent_did: "did:web:someone.else",
      op: "authenticate",
      reason: "verified",
      service_did: SERVICE_DID,
      verified: true
    });
    await expect(verifier(wrongAgent, context)).rejects.toThrow(/did not recognize/u);

    const wrongOp = hostedVerifier({
      agent_did: AGENT_DID,
      op: "enroll",
      reason: "verified",
      service_did: SERVICE_DID,
      verified: true
    });
    await expect(verifier(wrongOp, context)).rejects.toThrow(/did not recognize/u);

    const wrongService = hostedVerifier({
      agent_did: AGENT_DID,
      op: "authenticate",
      reason: "verified",
      service_did: "did:web:other.example",
      verified: true
    });
    await expect(verifier(wrongService, context)).rejects.toThrow(/did not recognize/u);

    async function verifier(
      candidate: ReturnType<typeof hostedVerifier>,
      ctx: typeof context
    ): Promise<unknown> {
      return candidate(assertion, ctx);
    }
  });

  it("rejects a non-2xx Platform response and a malformed body", async () => {
    const context = {
      clientAssertion: assertion,
      command: "authenticate" as const,
      resource: RESOURCE,
      serviceDid: SERVICE_DID,
      signingAlgorithms: ["EdDSA" as const]
    };

    await expect(hostedVerifier({}, 503)(assertion, context)).rejects.toThrow(/HTTP 503/u);
    await expect(hostedVerifier(["nope"] as never)(assertion, context)).rejects.toThrow(
      /must be an object/u
    );
    await expect(
      hostedVerifier({ service_did: SERVICE_DID, verified: true })(assertion, context)
    ).rejects.toThrow(/Expected string field: reason/u);
    await expect(
      hostedVerifier({ reason: "verified", service_did: SERVICE_DID })(assertion, context)
    ).rejects.toThrow(/Expected boolean field: verified/u);
  });

  it("requires a fetch implementation", () => {
    expect(() =>
      createHostedPlatformClientAssertionVerifier({
        endpoint: "https://platform.example/v",
        fetch: "nope" as never
      })
    ).toThrow(/requires a fetch implementation/u);
  });
});

describe("session credentials are compared without leaking their contents", () => {
  function apiKeyService(records: AepServiceCredentialRecord[], headerNames: string[]) {
    const store = createInMemoryServiceCredentialStore(records);

    return {
      service: createAepService(
        serviceOptions({
          authenticationMethods: ["api-key"],
          grantTypes: [
            storedApiKeyGrantType({
              clock: () => NOW,
              config: { header_names: headerNames },
              issue: () => {
                throw new Error("not issued in this test");
              },
              store
            })
          ]
        })
      ),
      store
    };
  }

  it("authenticates a single valid API key", async () => {
    const { service } = apiKeyService(
      [apiKeyRecord(AGENT_DID, "cred-1", "key-one", "x-api-key", ["orders:read"])],
      ["x-api-key"]
    );

    const result = await service.authenticateProtectedResource({
      headers: { "x-api-key": "key-one" },
      method: "GET",
      url: RESOURCE
    });

    expect(result).toMatchObject({
      authenticated: true,
      principal: {
        agentDid: AGENT_DID,
        authenticationKind: "session-credential",
        authenticationMethod: "api-key",
        credentialId: "cred-1",
        scopes: ["orders:read"]
      }
    });
  });

  it("refuses a presentation that resolves to two different identities", async () => {
    const { service } = apiKeyService(
      [
        apiKeyRecord("did:web:agent-one.example", "cred-1", "key-one", "x-api-key"),
        apiKeyRecord("did:web:agent-two.example", "cred-2", "key-two", "x-tenant-key")
      ],
      ["x-api-key", "x-tenant-key"]
    );

    const result = await service.authenticateProtectedResource({
      headers: { "x-api-key": "key-one", "x-tenant-key": "key-two" },
      method: "GET",
      url: RESOURCE
    });

    expect(result.authenticated).toBe(false);
  });

  it("refuses a presentation that resolves to two different scope sets for one identity", async () => {
    const { service } = apiKeyService(
      [
        apiKeyRecord(AGENT_DID, "cred-1", "key-one", "x-api-key", ["orders:read"]),
        apiKeyRecord(AGENT_DID, "cred-2", "key-two", "x-tenant-key", ["orders:write"])
      ],
      ["x-api-key", "x-tenant-key"]
    );

    await expect(
      service.authenticateProtectedResource({
        headers: { "x-api-key": "key-one", "x-tenant-key": "key-two" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("accepts a presentation matching two equivalent credentials for one identity", async () => {
    const { service } = apiKeyService(
      [
        apiKeyRecord(AGENT_DID, "cred-1", "key-one", "x-api-key", ["orders:read"]),
        apiKeyRecord(AGENT_DID, "cred-2", "key-two", "x-tenant-key", ["orders:read"])
      ],
      ["x-api-key", "x-tenant-key"]
    );

    await expect(
      service.authenticateProtectedResource({
        headers: { "x-api-key": "key-one", "x-tenant-key": "key-two" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: true });
  });

  it("only accepts the header the credential names", async () => {
    const { service } = apiKeyService(
      [apiKeyRecord(AGENT_DID, "cred-1", "key-one", "x-api-key")],
      ["x-api-key", "x-other-key"]
    );

    await expect(
      service.authenticateProtectedResource({
        headers: { "x-other-key": "key-one" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("ignores revoked and expired credentials", async () => {
    const expired = apiKeyRecord(AGENT_DID, "cred-expired", "key-one", "x-api-key");
    const store = createInMemoryServiceCredentialStore([
      {
        ...expired,
        credential: { ...expired.credential, expires_at: "2020-01-01T00:00:00.000Z" },
        expiresAt: "2020-01-01T00:00:00.000Z"
      }
    ]);

    const service = createAepService(
      serviceOptions({
        authenticationMethods: ["api-key"],
        grantTypes: [
          storedApiKeyGrantType({
            clock: () => NOW,
            issue: () => {
              throw new Error("not issued");
            },
            store
          })
        ]
      })
    );

    await expect(
      service.authenticateProtectedResource({
        headers: { "x-api-key": "key-one" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });

    await store.revokeGrantType(AGENT_DID, "api-key", "2026-05-28T12:00:00.000Z");
  });

  it("matches a Bearer token and a Basic credential on either carrier", async () => {
    const bearerStore = createInMemoryServiceCredentialStore([
      {
        agentDid: AGENT_DID,
        createdAt: "2026-05-28T12:00:00.000Z",
        credential: storedCredentialFixture({
          access_token: "token-value",
          credential_id: "cred-bearer",
          expires_at: FUTURE,
          scopes: [],
          token_type: "Bearer"
        }),
        credentialId: "cred-bearer",
        expiresAt: FUTURE,
        grantType: "oauth-bearer"
      }
    ]);

    const bearerService = createAepService(
      serviceOptions({
        authenticationMethods: ["oauth-bearer"],
        grantTypes: [
          storedOAuthBearerGrantType({
            clock: () => NOW,
            issue: () => {
              throw new Error("not issued");
            },
            store: bearerStore
          })
        ]
      })
    );

    await expect(
      bearerService.authenticateProtectedResource({
        headers: { authorization: "Bearer token-value" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: true });

    await expect(
      bearerService.authenticateProtectedResource({
        headers: { "aep-authorization": "Bearer token-value" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: true });

    await expect(
      bearerService.authenticateProtectedResource({
        headers: { authorization: "Bearer wrong-value" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });

    await expect(
      bearerService.authenticateProtectedResource({
        headers: { authorization: "not a valid credential" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });

    const basicValue = Buffer.from("user:pass").toString("base64");
    const basicStore = createInMemoryServiceCredentialStore([
      {
        agentDid: AGENT_DID,
        createdAt: "2026-05-28T12:00:00.000Z",
        credential: storedCredentialFixture({
          credential_id: "cred-basic",
          expires_at: FUTURE,
          password: "pass",
          scopes: [],
          username: "user"
        }),
        credentialId: "cred-basic",
        expiresAt: FUTURE,
        grantType: "basic"
      }
    ]);

    const basicService = createAepService(
      serviceOptions({
        authenticationMethods: ["basic"],
        grantTypes: [
          storedBasicGrantType({
            clock: () => NOW,
            issue: () => {
              throw new Error("not issued");
            },
            store: basicStore
          })
        ]
      })
    );

    await expect(
      basicService.authenticateProtectedResource({
        headers: { authorization: `Basic ${basicValue}` },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: true });

    await expect(
      basicService.authenticateProtectedResource({
        headers: { authorization: `Basic ${Buffer.from("user:wrong").toString("base64")}` },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("issues, stores, and revokes a credential through the stored grant type", async () => {
    const store = createInMemoryServiceCredentialStore();
    const enrollmentStore = createInMemoryEnrollmentStore([
      {
        agentDid: AGENT_DID,
        claims: {},
        createdAt: "2026-05-28T12:00:00.000Z",
        ownerActionRequired: false,
        requirementsPending: [],
        since: "2026-05-28T12:00:00.000Z",
        status: "active",
        updatedAt: "2026-05-28T12:00:00.000Z"
      }
    ]);

    let issued = 0;
    const service = createAepService(
      serviceOptions({
        authenticationMethods: ["api-key"],
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier(),
        enrollmentStore,
        grantTypes: [
          storedApiKeyGrantType({
            clock: () => NOW,
            issue: () => {
              issued += 1;
              return {
                api_key: `issued-key-${String(issued)}`,
                credential_id: `cred-${String(issued)}`,
                expires_at: FUTURE,
                header: "x-api-key",
                scopes: ["orders:read"]
              };
            },
            store
          })
        ]
      })
    );

    const granted = await service.grant(
      { grant_type: "api-key", requested_scopes: ["orders:read"] },
      {
        clientAssertion: encoded(claims({ jti: "jti-grant", op: "grant" })),
        idempotencyKey: "idem-grant"
      }
    );

    expect(granted.status).toBe(200);
    expect(granted.body).toMatchObject({ api_key: "issued-key-1", header: "x-api-key" });
    expect(await store.listCredentials(AGENT_DID, "api-key")).toHaveLength(1);

    const revoked = await service.revoke(
      { credential_id: "cred-1", grant_type: "api-key" },
      {
        clientAssertion: encoded(claims({ jti: "jti-revoke", op: "revoke" })),
        idempotencyKey: "idem-revoke"
      }
    );

    expect(revoked.status).toBe(200);
    expect(revoked.body).toEqual({});

    const all = await store.listCredentials(AGENT_DID, "api-key");
    expect(all[0]?.revokedAt).toBeTypeOf("string");

    await store.revokeGrantType(AGENT_DID, "api-key", "2026-05-28T13:00:00.000Z");
  });

  it("refuses a credential store record whose body disagrees with its metadata", () => {
    const record = apiKeyRecord(AGENT_DID, "cred-1", "key-one", "x-api-key");

    expect(() =>
      createInMemoryServiceCredentialStore([{ ...record, credentialId: "cred-other" }])
    ).toThrow(/credentialId does not match/u);

    expect(() =>
      createInMemoryServiceCredentialStore([{ ...record, expiresAt: "2030-01-01T00:00:00.000Z" }])
    ).toThrow(/expiresAt does not match/u);

    expect(() => createInMemoryServiceCredentialStore([record, record])).toThrow(/already issued/u);
  });
});

describe("baseline AEP authentication on commands", () => {
  function service(overrides: Partial<AepServiceOptions> = {}) {
    return createAepService(
      serviceOptions({
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier(),
        enrollmentStore: createInMemoryEnrollmentStore(),
        ...overrides
      })
    );
  }

  it("refuses every command when no verifier is configured", async () => {
    const bare = createAepService(serviceOptions());
    const options = { clientAssertion: "anything", idempotencyKey: "k" };

    for (const response of [
      await bare.enroll({ agent_did: AGENT_DID }, options),
      await bare.grant({ grant_type: "oauth-bearer" }, options),
      await bare.revoke({ all_grant_types: "true" }, options),
      await bare.status(options)
    ]) {
      expect(response.status).toBe(401);
      expect(response.body).toMatchObject({ code: "not_recognized" });
      expect(response.headers?.["WWW-Authenticate"]).toBe('AEP reason="not_recognized"');
    }
  });

  it("rejects an assertion the verifier throws on", async () => {
    const failing = service({
      clientAssertionVerifier: () => {
        throw new Error("bad signature");
      }
    });

    await expect(
      failing.status({ clientAssertion: "x", idempotencyKey: "k" })
    ).resolves.toMatchObject({ status: 401 });
  });

  it.each([
    ["iss that does not equal sub", claims({ iss: "did:web:other.example", op: "status" })],
    ["aud naming another Service", claims({ aud: "did:web:other.example", op: "status" })],
    ["an op that does not match the command", claims({ op: "enroll" })],
    ["a resource on a non-authenticate assertion", claims({ op: "status", resource: RESOURCE })],
    ["exp at or before iat", claims({ exp: Math.floor(NOW.getTime() / 1000), op: "status" })],
    [
      "a lifetime over the configured maximum",
      claims({ exp: Math.floor(NOW.getTime() / 1000) + 3600, op: "status" })
    ],
    [
      "iat too far in the future",
      claims({
        exp: Math.floor(NOW.getTime() / 1000) + 4000,
        iat: Math.floor(NOW.getTime() / 1000) + 3700,
        op: "status"
      })
    ],
    [
      "exp already past",
      claims({
        exp: Math.floor(NOW.getTime() / 1000) - 3600,
        iat: Math.floor(NOW.getTime() / 1000) - 3900,
        op: "status"
      })
    ]
  ])("rejects an assertion with %s", async (_label, payload) => {
    const response = await service().status({
      clientAssertion: encoded(payload),
      idempotencyKey: "k"
    });

    expect(response.status).toBe(401);
  });

  it("refuses to reuse a jti", async () => {
    const configured = service({
      enrollmentStore: createInMemoryEnrollmentStore([
        {
          agentDid: AGENT_DID,
          claims: {},
          createdAt: "2026-05-28T12:00:00.000Z",
          ownerActionRequired: false,
          requirementsPending: [],
          since: "2026-05-28T12:00:00.000Z",
          status: "active",
          updatedAt: "2026-05-28T12:00:00.000Z"
        }
      ]),
      replayStore: createInMemoryClientAssertionReplayStore()
    });

    const assertion = encoded(claims({ jti: "jti-replay", op: "status" }));

    await expect(
      configured.status({ clientAssertion: assertion, idempotencyKey: "k" })
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      configured.status({ clientAssertion: assertion, idempotencyKey: "k" })
    ).resolves.toMatchObject({ status: 401 });
  });

  it("refuses an Enroll whose agent_did is not the authenticated subject", async () => {
    const response = await service().enroll(
      { agent_did: "did:web:someone.else" },
      { clientAssertion: encoded(claims()), idempotencyKey: "k" }
    );

    expect(response).toMatchObject({ body: { code: "not_recognized" }, status: 401 });
  });

  it("refuses an Enroll body it cannot parse before looking at the subject", async () => {
    const response = await service().enroll(
      { agent_did: 42 },
      { clientAssertion: encoded(claims()), idempotencyKey: "k" }
    );

    expect(response).toMatchObject({ body: { code: "invalid_request" }, status: 400 });
  });

  it("reports status for an enrolled Agent", async () => {
    const store = createInMemoryEnrollmentStore();
    const configured = service({ enrollmentStore: store });

    await configured.enroll(
      { agent_did: AGENT_DID },
      { clientAssertion: encoded(claims({ jti: "jti-a" })), idempotencyKey: "idem-a" }
    );

    const status = await configured.status({
      clientAssertion: encoded(claims({ jti: "jti-b", op: "status" })),
      idempotencyKey: "idem-b"
    });

    expect(status).toMatchObject({ body: { status: "active" }, status: 200 });
  });

  it("authenticates a protected resource with a baseline assertion", async () => {
    const configured = createAepService(
      serviceOptions({
        authenticationMethods: ["aep-jwt"],
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier()
      })
    );

    const assertion = encoded(
      claims({ jti: "jti-authenticate", op: "authenticate", resource: RESOURCE })
    );

    await expect(
      configured.authenticateProtectedResource({
        headers: { authorization: `AEP ${assertion}` },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({
      authenticated: true,
      principal: { agentDid: AGENT_DID, authenticationKind: "aep-jwt" }
    });
  });

  it("refuses a baseline assertion when aep-jwt is not advertised", async () => {
    const configured = createAepService(
      serviceOptions({
        authenticationMethods: ["api-key"],
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier()
      })
    );

    const result = await configured.authenticateProtectedResource({
      headers: { authorization: "AEP anything" },
      method: "GET",
      url: RESOURCE
    });

    if (result.authenticated) throw new Error("unreachable");

    expect(result.response.body.code).toBe("unsupported_authentication_method");
  });

  it("extracts an assertion from an AEP Authorization value", () => {
    expect(clientAssertionFromAepAuthorization("AEP abc.def.ghi")).toBe("abc.def.ghi");
    expect(clientAssertionFromAepAuthorization("Bearer abc")).toBe("");
    expect(clientAssertionFromAepAuthorization(null)).toBe("");
    expect(clientAssertionFromAepAuthorization(undefined)).toBe("");
  });
});

describe("ambiguous and malformed authorization carriers", () => {
  function service() {
    return createAepService(
      serviceOptions({
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier()
      })
    );
  }

  it("refuses a repeated dedicated field", async () => {
    const configured = service();

    await expect(
      configured.authenticateProtectedResource({
        headers: { "aep-authorization": ["AEP a", "AEP b"] },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });

    const headers = new Headers();
    headers.append("aep-authorization", "AEP a");
    headers.append("aep-authorization", "AEP b");

    await expect(
      configured.authenticateProtectedResource({ headers, method: "GET", url: RESOURCE })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("refuses a malformed dedicated field", async () => {
    await expect(
      service().authenticateProtectedResource({
        headers: { "aep-authorization": "!!! not a credential" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("refuses a recognized scheme on both carriers at once", async () => {
    const assertion = encoded(claims({ op: "authenticate", resource: RESOURCE }));

    await expect(
      service().authenticateProtectedResource({
        headers: { "aep-authorization": `AEP ${assertion}`, authorization: "Bearer token" },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("lets an unrelated Authorization scheme compose with the dedicated field", async () => {
    const assertion = encoded(
      claims({ jti: "jti-compose", op: "authenticate", resource: RESOURCE })
    );

    await expect(
      service().authenticateProtectedResource({
        headers: {
          "aep-authorization": `AEP ${assertion}`,
          authorization: "Negotiate something-unrelated"
        },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: true });
  });

  it("reads headers from a Headers instance and joins repeated plain values", async () => {
    const headers = new Headers({ authorization: "Bearer token-value" });
    const configured = createAepService(
      serviceOptions({
        authenticationMethods: ["aep-jwt"],
        clientAssertionVerifier: jsonVerifier()
      })
    );

    await expect(
      configured.authenticateProtectedResource({ headers, method: "GET", url: RESOURCE })
    ).resolves.toMatchObject({ authenticated: false });

    await expect(
      configured.authenticateProtectedResource({
        headers: { "x-multi": ["a", "b"] },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });
  });
});

describe("Enroll claim limits", () => {
  const options = () => ({
    claimValueLimits: DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS,
    idempotencyKey: "idem-1",
    policy: createStaticEnrollmentPolicy(),
    store: createInMemoryEnrollmentStore()
  });

  it("exports the default limits", () => {
    expect(DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS).toMatchObject({
      maxEncodedBytes: expect.any(Number) as number,
      maxMemberCount: expect.any(Number) as number,
      maxObjectDepth: expect.any(Number) as number,
      maxStringLength: expect.any(Number) as number
    });
  });

  it("rejects an over-long string, too many members, and excessive depth", async () => {
    const long = "x".repeat(DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS.maxStringLength + 1);

    await expect(
      handleEnrollRequest({ agent_did: AGENT_DID, claims: { "agent.name": long } }, options())
    ).resolves.toMatchObject({ body: { code: "invalid_request" }, status: 400 });

    const many: Record<string, unknown> = {};
    for (
      let index = 0;
      index <= DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS.maxMemberCount;
      index += 1
    ) {
      many[`k${String(index)}`] = index;
    }

    await expect(
      handleEnrollRequest({ agent_did: AGENT_DID, claims: { "agent.name": many } }, options())
    ).resolves.toMatchObject({ status: 400 });

    let deep: unknown = "leaf";
    for (
      let index = 0;
      index <= DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS.maxObjectDepth;
      index += 1
    ) {
      deep = { nested: deep };
    }

    await expect(
      handleEnrollRequest({ agent_did: AGENT_DID, claims: { "agent.name": deep } }, options())
    ).resolves.toMatchObject({ status: 400 });
  });

  it("rejects a cyclic claim value and a non-plain object", async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;

    await expect(
      handleEnrollRequest({ agent_did: AGENT_DID, claims: { "agent.name": cyclic } }, options())
    ).resolves.toMatchObject({ status: 400 });

    await expect(
      handleEnrollRequest({ agent_did: AGENT_DID, claims: { "agent.name": new Date() } }, options())
    ).resolves.toMatchObject({ status: 400 });

    await expect(
      handleEnrollRequest(
        { agent_did: AGENT_DID, claims: { "agent.name": Number.POSITIVE_INFINITY } },
        options()
      )
    ).resolves.toMatchObject({ status: 400 });
  });

  it("accepts values inside the limits, including nested arrays", async () => {
    await expect(
      handleEnrollRequest(
        {
          agent_did: AGENT_DID,
          claims: { "agent.name": { list: [1, "two", true, null], nested: { ok: true } } }
        },
        options()
      )
    ).resolves.toMatchObject({ status: 200 });
  });

  it("honours a caller-supplied limit override", async () => {
    await expect(
      handleEnrollRequest(
        { agent_did: AGENT_DID, claims: { "agent.name": "abcdef" } },
        { ...options(), claimValueLimits: { maxStringLength: 3 } }
      )
    ).resolves.toMatchObject({ status: 400 });
  });
});

describe("command handlers outside the engine", () => {
  const enrollment = {
    agentDid: AGENT_DID,
    claims: {},
    createdAt: "2026-05-28T12:00:00.000Z",
    ownerActionRequired: false,
    requirementsPending: [],
    since: "2026-05-28T12:00:00.000Z",
    status: "active" as const,
    updatedAt: "2026-05-28T12:00:00.000Z"
  };

  it("supports a custom store with no optional verification list on pending enrollment", async () => {
    const record = { ...enrollment, status: "pending" as const };
    const store = {
      findEnrollment: () => record,
      saveEnrollment: () => {
        throw new Error("Existing enrollment must not be replaced");
      }
    };
    const enrolled = await handleEnrollRequest(
      { agent_did: AGENT_DID },
      {
        store,
        idempotencyKey: "existing",
        policy: createStaticEnrollmentPolicy()
      }
    );
    const status = await handleStatusRequest(AGENT_DID, { store });
    const grant = await handleGrantRequest(
      { grant_type: "oauth-bearer" },
      {
        store,
        agentDid: AGENT_DID,
        handlers: new Map(),
        idempotencyKey: "pending-grant"
      }
    );
    expect(enrolled).toMatchObject({ status: 200, body: { status: "pending" } });
    expect(status).toMatchObject({ status: 200, body: { status: "pending" } });
    expect(grant).toMatchObject({ status: 403, body: { code: "verification_pending" } });
    for (const response of [enrolled, status, grant]) {
      expect(response.body).not.toHaveProperty("verification_pending");
      expect(response.body).not.toHaveProperty("requirements_pending");
    }
  });

  it("requires a non-empty idempotency key on every idempotent command", async () => {
    const store = createInMemoryEnrollmentStore([enrollment]);
    const handlers = new Map([["oauth-bearer" as const, { grant: () => ({}), revoke: () => {} }]]);

    await expect(
      handleEnrollRequest(
        { agent_did: AGENT_DID },
        { idempotencyKey: "   ", policy: createStaticEnrollmentPolicy(), store }
      )
    ).resolves.toMatchObject({ status: 400 });

    await expect(
      handleGrantRequest(
        { grant_type: "oauth-bearer" },
        { agentDid: AGENT_DID, handlers, idempotencyKey: "", store }
      )
    ).resolves.toMatchObject({ status: 400 });

    await expect(
      handleRevokeRequest(
        { all_grant_types: "true" },
        { agentDid: AGENT_DID, handlers, idempotencyKey: "", store }
      )
    ).resolves.toMatchObject({ status: 400 });
  });

  it("rejects a body it cannot parse", async () => {
    const store = createInMemoryEnrollmentStore([enrollment]);
    const handlers = new Map([["oauth-bearer" as const, { grant: () => ({}), revoke: () => {} }]]);

    await expect(
      handleEnrollRequest(null, {
        idempotencyKey: "k",
        policy: createStaticEnrollmentPolicy(),
        store
      })
    ).resolves.toMatchObject({ status: 400 });

    await expect(
      handleGrantRequest(null, { agentDid: AGENT_DID, handlers, idempotencyKey: "k", store })
    ).resolves.toMatchObject({ status: 400 });

    await expect(
      handleRevokeRequest(null, { agentDid: AGENT_DID, handlers, idempotencyKey: "k", store })
    ).resolves.toMatchObject({ status: 400 });
  });

  it("refuses an Enroll whose embedded idempotency key disagrees with the header", async () => {
    await expect(
      handleEnrollRequest(
        { agent_did: AGENT_DID, idempotency_key: "body-key" },
        {
          idempotencyKey: "header-key",
          policy: createStaticEnrollmentPolicy(),
          store: createInMemoryEnrollmentStore()
        }
      )
    ).resolves.toMatchObject({ status: 400 });
  });

  it("reports requirements_unmet when a required claim is missing", async () => {
    const response = await handleEnrollRequest(
      { agent_did: AGENT_DID },
      {
        idempotencyKey: "k",
        policy: createStaticEnrollmentPolicy(),
        requiredClaims: ["contact.email"],
        store: createInMemoryEnrollmentStore()
      }
    );

    expect(response.status).toBe(422);
    expect(response.body).toMatchObject({
      code: "requirements_unmet",
      requirements_pending: ["contact.email"]
    });
  });

  it("returns the existing record for a repeated Enroll", async () => {
    const store = createInMemoryEnrollmentStore([enrollment]);

    await expect(
      handleEnrollRequest(
        { agent_did: AGENT_DID },
        { idempotencyKey: "k", policy: createStaticEnrollmentPolicy(), store }
      )
    ).resolves.toMatchObject({ body: { status: "active" }, status: 200 });
  });

  it("reports not_recognized for an unknown Agent", async () => {
    const empty = createInMemoryEnrollmentStore();
    const handlers = new Map([["oauth-bearer" as const, { grant: () => ({}), revoke: () => {} }]]);

    await expect(handleStatusRequest(AGENT_DID, { store: empty })).resolves.toMatchObject({
      status: 401
    });
    await expect(
      handleGrantRequest(
        { grant_type: "oauth-bearer" },
        { agentDid: AGENT_DID, handlers, idempotencyKey: "k", store: empty }
      )
    ).resolves.toMatchObject({ status: 401 });
    await expect(
      handleRevokeRequest(
        { all_grant_types: "true" },
        { agentDid: AGENT_DID, handlers, idempotencyKey: "k", store: empty }
      )
    ).resolves.toMatchObject({ status: 401 });
  });

  it("reports unsupported_grant_type for a grant type with no handler", async () => {
    const store = createInMemoryEnrollmentStore([enrollment]);
    const handlers = new Map<never, never>();

    await expect(
      handleGrantRequest(
        { grant_type: "oauth-bearer" },
        { agentDid: AGENT_DID, handlers, idempotencyKey: "k", store }
      )
    ).resolves.toMatchObject({ body: { code: "unsupported_grant_type" }, status: 400 });

    await expect(
      handleRevokeRequest(
        { grant_type: "oauth-bearer" },
        { agentDid: AGENT_DID, handlers, idempotencyKey: "k", store }
      )
    ).resolves.toMatchObject({ body: { code: "unsupported_grant_type" }, status: 400 });
  });

  it("reports verification_pending when the enrollment is not active", async () => {
    const pending = createInMemoryEnrollmentStore([
      {
        ...enrollment,
        requirementsPending: ["contact.email"],
        status: "pending",
        verificationPending: ["contact.email"]
      }
    ]);
    const handlers = new Map([["oauth-bearer" as const, { grant: () => ({}), revoke: () => {} }]]);

    const response = await handleGrantRequest(
      { grant_type: "oauth-bearer" },
      { agentDid: AGENT_DID, handlers, idempotencyKey: "k", store: pending }
    );

    expect(response.status).toBe(403);
    expect(response.body).toMatchObject({ code: "verification_pending" });
  });

  it("revokes every advertised grant type when none is named", async () => {
    const seen: string[] = [];
    const handlers = new Map([
      [
        "oauth-bearer" as const,
        {
          grant: () => ({}),
          revoke: (_request: unknown, context: { grantType: string }) => {
            seen.push(context.grantType);
          }
        }
      ],
      [
        "api-key" as const,
        {
          grant: () => ({}),
          revoke: (_request: unknown, context: { grantType: string }) => {
            seen.push(context.grantType);
          }
        }
      ]
    ]);

    const response = await handleRevokeRequest(
      { all_grant_types: "true" },
      {
        agentDid: AGENT_DID,
        handlers,
        idempotencyKey: "k",
        store: createInMemoryEnrollmentStore([enrollment])
      }
    );

    expect(response).toMatchObject({ body: {}, status: 200 });
    expect(seen).toEqual(["oauth-bearer", "api-key"]);
  });
});

describe("command idempotency", () => {
  it("preserves response headers on replay and isolates them from caller mutation", async () => {
    const backing = createInMemoryCommandIdempotencyStore();
    const service = createAepService(
      serviceOptions({
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier(),
        enrollmentStore: createInMemoryEnrollmentStore(),
        commandIdempotencyStore: {
          executeIdempotentCommand: (input, execute) =>
            backing.executeIdempotentCommand(input, async () => ({
              ...(await execute()),
              headers: { "X-Trace": "original" }
            }))
        }
      })
    );
    for (const jti of ["first", "second", "third"]) {
      const response = await service.enroll(
        { agent_did: AGENT_DID },
        {
          clientAssertion: encoded(claims({ jti })),
          idempotencyKey: "same-command"
        }
      );
      expect(response.status).toBe(200);
      expect(response.headers).toEqual({ "X-Trace": "original" });
      if (response.headers === undefined) throw new Error("missing headers");
      response.headers["X-Trace"] = "caller-mutated";
    }
  });

  it("replays a stored response and reports a conflict on changed material", async () => {
    const store = createInMemoryCommandIdempotencyStore();
    const enrollmentStore = createInMemoryEnrollmentStore();
    const service = createAepService(
      serviceOptions({
        clientAssertion: { clock: () => NOW },
        clientAssertionVerifier: jsonVerifier(),
        commandIdempotencyStore: store,
        enrollmentStore
      })
    );

    const first = await service.enroll(
      { agent_did: AGENT_DID, claims: { "agent.name": "One" } },
      { clientAssertion: encoded(claims({ jti: "j1" })), idempotencyKey: "idem-1" }
    );

    const replay = await service.enroll(
      { agent_did: AGENT_DID, claims: { "agent.name": "One" } },
      { clientAssertion: encoded(claims({ jti: "j2" })), idempotencyKey: "idem-1" }
    );

    expect(replay).toEqual(first);

    const conflict = await service.enroll(
      { agent_did: AGENT_DID, claims: { "agent.name": "Two" } },
      { clientAssertion: encoded(claims({ jti: "j3" })), idempotencyKey: "idem-1" }
    );

    expect(conflict).toMatchObject({ body: { code: "idempotency_conflict" }, status: 409 });
  });

  it("replays a seeded record without executing the command", async () => {
    const store = createInMemoryCommandIdempotencyStore([
      {
        agentDid: AGENT_DID,
        body: { status: "active" },
        command: "enroll",
        contentType: "application/aep+json",
        createdAt: "2026-05-28T12:00:00.000Z",
        idempotencyKey: "idem-seeded",
        requestHash: "sha256:seeded",
        status: 200
      }
    ]);

    const replayed = await store.executeIdempotentCommand(
      {
        agentDid: AGENT_DID,
        command: "enroll",
        idempotencyKey: "idem-seeded",
        requestHash: "sha256:seeded"
      },
      () => {
        throw new Error("should not re-execute");
      }
    );

    expect(replayed.state).toBe("replayed");

    const conflict = await store.executeIdempotentCommand(
      {
        agentDid: AGENT_DID,
        command: "grant",
        idempotencyKey: "idem-seeded",
        requestHash: "sha256:seeded"
      },
      () => {
        throw new Error("should not execute");
      }
    );

    expect(conflict.state).toBe("conflict");
  });
});

describe("remaining store and grant-type behaviour", () => {
  it("returns no credential for an unknown identifier", async () => {
    const store = createInMemoryServiceCredentialStore([
      apiKeyRecord(AGENT_DID, "known", "secret", "X-Key")
    ]);
    expect(await store.findCredential(AGENT_DID, "api-key", "missing")).toBeUndefined();
    expect(await store.findCredential(AGENT_DID, "api-key", "known")).toMatchObject({
      credentialId: "known"
    });
  });

  it("evicts an expired replay record before rejecting a reuse", () => {
    const store = createInMemoryClientAssertionReplayStore();

    expect(store.consumeReplay({ expiresAt: 100, jti: "old", sub: AGENT_DID }, 50)).toBe(true);
    // Past the first record's expiry, its slot is reclaimed and the same jti is usable again.
    expect(store.consumeReplay({ expiresAt: 400, jti: "new", sub: AGENT_DID }, 200)).toBe(true);
    expect(store.consumeReplay({ expiresAt: 400, jti: "old", sub: AGENT_DID }, 200)).toBe(true);
    expect(store.consumeReplay({ expiresAt: 400, jti: "new", sub: AGENT_DID }, 200)).toBe(false);
  });

  it("defaults the stored grant type clock to the wall clock", async () => {
    const store = createInMemoryServiceCredentialStore();
    const definition = storedApiKeyGrantType({
      issue: () => ({
        api_key: "issued-key",
        credential_id: "cred-default-clock",
        expires_at: FUTURE,
        header: "x-api-key",
        scopes: []
      }),
      store
    });

    const before = Date.now();
    await definition.handler?.grant(
      { grant_type: "api-key" },
      { agentDid: AGENT_DID, enrollment: undefined as never, grantType: "api-key" }
    );

    const [record] = await store.listCredentials(AGENT_DID, "api-key");
    expect(Date.parse(record?.createdAt ?? "")).toBeGreaterThanOrEqual(before);

    await definition.handler?.revoke(
      { grant_type: "api-key" },
      { agentDid: AGENT_DID, enrollment: undefined as never, grantType: "api-key" }
    );

    const [revoked] = await store.listCredentials(AGENT_DID, "api-key");
    expect(revoked?.revokedAt).toBeTypeOf("string");
  });

  it("reports authentication_required when nothing at all is presented", async () => {
    const store = createInMemoryServiceCredentialStore([
      {
        agentDid: AGENT_DID,
        createdAt: "2026-05-28T12:00:00.000Z",
        credential: storedCredentialFixture({
          access_token: "token-value",
          credential_id: "cred-bearer",
          expires_at: FUTURE,
          scopes: [],
          token_type: "Bearer"
        }),
        credentialId: "cred-bearer",
        expiresAt: FUTURE,
        grantType: "oauth-bearer"
      }
    ]);

    const service = createAepService(
      serviceOptions({
        authenticationMethods: ["oauth-bearer"],
        grantTypes: [
          storedOAuthBearerGrantType({
            clock: () => NOW,
            issue: () => {
              throw new Error("not issued");
            },
            store
          })
        ]
      })
    );

    const result = await service.authenticateProtectedResource({
      headers: {},
      method: "GET",
      url: RESOURCE
    });

    if (result.authenticated) throw new Error("unreachable");

    expect(result.response.body.code).toBe("authentication_required");
  });
});

describe("defaults and response shaping", () => {
  it("uses the wall clock when no assertion clock is configured", async () => {
    const iat = Math.floor(Date.now() / 1000);
    const service = createAepService(
      serviceOptions({
        clientAssertionVerifier: jsonVerifier(),
        enrollmentStore: createInMemoryEnrollmentStore()
      })
    );

    const response = await service.enroll(
      { agent_did: AGENT_DID },
      {
        clientAssertion: encoded(claims({ exp: iat + 300, iat, jti: "jti-wallclock" })),
        idempotencyKey: "idem-wallclock"
      }
    );

    expect(response.status).toBe(200);
  });

  it("fills in every enrollment decision default", async () => {
    const store = createInMemoryEnrollmentStore();
    const response = await handleEnrollRequest(
      { agent_did: AGENT_DID },
      {
        clock: () => NOW,
        idempotencyKey: "idem-defaults",
        policy: { decideEnrollment: () => ({}) },
        store
      }
    );

    expect(response).toMatchObject({ body: { status: "active" }, status: 200 });

    const record = await store.findEnrollment(AGENT_DID);
    expect(record).toMatchObject({
      ownerActionRequired: false,
      requirementsPending: [],
      status: "active",
      verificationPending: []
    });
  });

  it("carries owner action, requirements, and verification into Enroll and Status bodies", async () => {
    const store = createInMemoryEnrollmentStore();
    await handleEnrollRequest(
      { agent_did: AGENT_DID },
      {
        clock: () => NOW,
        idempotencyKey: "idem-pending",
        policy: {
          decideEnrollment: () => ({
            ownerActionRequired: true,
            requirementsPending: ["contact.email"],
            status: "pending",
            verificationPending: ["contact.email"]
          })
        },
        store
      }
    );

    const status = await handleStatusRequest(AGENT_DID, { store });

    expect(status.body).toMatchObject({
      owner_action_required: "true",
      requirements_pending: ["contact.email"],
      since: "2026-05-28T12:00:00.000Z",
      status: "pending",
      verification_pending: ["contact.email"]
    });
  });

  it("reports requirements_pending and verification_pending separately on a blocked Grant", async () => {
    const handlers = new Map([["oauth-bearer" as const, { grant: () => ({}), revoke: () => {} }]]);

    const requirementsOnly = await handleGrantRequest(
      { grant_type: "oauth-bearer" },
      {
        agentDid: AGENT_DID,
        handlers,
        idempotencyKey: "k",
        store: createInMemoryEnrollmentStore([
          {
            agentDid: AGENT_DID,
            claims: {},
            createdAt: "2026-05-28T12:00:00.000Z",
            ownerActionRequired: false,
            requirementsPending: ["contact.email"],
            since: "2026-05-28T12:00:00.000Z",
            status: "pending",
            updatedAt: "2026-05-28T12:00:00.000Z"
          }
        ])
      }
    );

    expect(requirementsOnly.body).toMatchObject({ requirements_pending: ["contact.email"] });

    const neither = await handleGrantRequest(
      { grant_type: "oauth-bearer" },
      {
        agentDid: AGENT_DID,
        handlers,
        idempotencyKey: "k",
        store: createInMemoryEnrollmentStore([
          {
            agentDid: AGENT_DID,
            claims: {},
            createdAt: "2026-05-28T12:00:00.000Z",
            ownerActionRequired: false,
            requirementsPending: [],
            since: "2026-05-28T12:00:00.000Z",
            status: "suspended",
            updatedAt: "2026-05-28T12:00:00.000Z"
          }
        ])
      }
    );

    expect(neither.status).toBe(403);
  });

  it("filters stored credentials by Agent and grant type", async () => {
    const store = createInMemoryServiceCredentialStore([
      apiKeyRecord("did:web:agent-one.example", "cred-1", "key-one", "x-api-key"),
      apiKeyRecord("did:web:agent-two.example", "cred-2", "key-two", "x-api-key")
    ]);

    expect(await store.listCredentials()).toHaveLength(2);
    expect(await store.listCredentials("did:web:agent-one.example")).toHaveLength(1);
    expect(await store.listCredentials(undefined, "oauth-bearer")).toHaveLength(0);
    expect(await store.listCredentials("did:web:nobody.example")).toHaveLength(0);

    // Revoking a credential that belongs to another Agent leaves it alone.
    await store.revokeCredential(
      "did:web:agent-two.example",
      "api-key",
      "cred-1",
      "2026-05-28T13:00:00.000Z"
    );
    expect((await store.listCredentials(undefined, "api-key"))[0]?.revokedAt).toBeUndefined();

    await store.revokeCredential(
      "did:web:agent-one.example",
      "api-key",
      "cred-1",
      "2026-05-28T13:00:00.000Z"
    );
    const [first] = await store.listCredentials("did:web:agent-one.example");
    expect(first?.revokedAt).toBe("2026-05-28T13:00:00.000Z");

    await store.revokeGrantType(
      "did:web:agent-two.example",
      "oauth-bearer",
      "2026-05-28T13:00:00.000Z"
    );
    const [second] = await store.listCredentials("did:web:agent-two.example");
    expect(second?.revokedAt).toBeUndefined();
  });

  it("refuses a Basic credential record with no usable username and password", async () => {
    const store: AepServiceCredentialStore = {
      listCredentials: () =>
        Promise.resolve([
          {
            agentDid: AGENT_DID,
            createdAt: "2026-05-28T12:00:00.000Z",
            credential: {
              credential_id: "cred-basic",
              expires_at: FUTURE,
              scopes: []
            } as never,
            credentialId: "cred-basic",
            expiresAt: FUTURE,
            grantType: "basic"
          }
        ]),
      findCredential: () => Promise.resolve(undefined),
      revokeCredential: () => Promise.resolve(),
      revokeGrantType: () => Promise.resolve(),
      saveCredential: (record) => Promise.resolve(record)
    };

    const service = createAepService(
      serviceOptions({
        authenticationMethods: ["basic"],
        grantTypes: [
          storedBasicGrantType({
            clock: () => NOW,
            issue: () => {
              throw new Error("not issued");
            },
            store
          })
        ]
      })
    );

    await expect(
      service.authenticateProtectedResource({
        headers: { authorization: `Basic ${Buffer.from("user:pass").toString("base64")}` },
        method: "GET",
        url: RESOURCE
      })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("omits the authentication block when no methods are advertised", () => {
    const document = buildInspectDocument({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: SERVICE_DID
    });

    expect(document.commands["authentication"]).toBeUndefined();
  });

  it("accepts a grant type definition with no handler", () => {
    const document = buildInspectDocument({
      grantTypes: [{ grantType: "handler-free" }],
      identityMethods: [didWebIdentityMethod()],
      serviceDid: SERVICE_DID
    });

    expect(document.commands.grant_types).toContain("handler-free");
  });

  it("detects a joined duplicate in a Headers instance", async () => {
    const headers = new Headers();
    headers.append("aep-authorization", "AEP abc");
    headers.append("aep-authorization", "AEP def");

    const service = createAepService(serviceOptions({ clientAssertionVerifier: jsonVerifier() }));

    await expect(
      service.authenticateProtectedResource({ headers, method: "GET", url: RESOURCE })
    ).resolves.toMatchObject({ authenticated: false });
  });

  it("falls back to the global fetch for hosted verification", () => {
    expect(() =>
      createHostedPlatformClientAssertionVerifier({ endpoint: "https://platform.example/v" })
    ).not.toThrow();
  });

  it("passes optional verifier settings through", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const iat = Math.floor(NOW.getTime() / 1000);
    const assertion = await signClientAssertionJwt(
      { ...claims({ exp: iat + 300, iat, op: "status" }) },
      { alg: "EdDSA", key: privateKey }
    );

    const verifier = createJwtClientAssertionVerifier({
      clockTolerance: "5 minutes",
      currentDate: NOW,
      key: publicKey
    });

    await expect(
      verifier(assertion, {
        clientAssertion: assertion,
        command: "status",
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      })
    ).resolves.toMatchObject({ op: "status" });

    const publicKeyJwk = publicKey.export({ format: "jwk" });
    const liveIat = Math.floor(Date.now() / 1000);
    const liveAssertion = await signClientAssertionJwt(
      { ...claims({ exp: liveIat + 300, iat: liveIat, op: "status" }) },
      { alg: "EdDSA", key: privateKey }
    );

    const didWeb = createDidWebClientAssertionVerifier({
      allowInsecureLoopback: true,
      fetch: () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              id: AGENT_DID,
              verificationMethod: [
                { controller: AGENT_DID, id: AGENT_DID, publicKeyJwk, type: "JsonWebKey2020" }
              ]
            }),
            { headers: { "content-type": "application/json" }, status: 200 }
          )
        )
    });

    await expect(
      didWeb(liveAssertion, {
        clientAssertion: liveAssertion,
        command: "status",
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      })
    ).resolves.toMatchObject({ sub: AGENT_DID });
  });
});

describe("Inspect construction", () => {
  it("rejects duplicate identity methods and grant types", () => {
    expect(() =>
      buildInspectDocument({
        identityMethods: [didWebIdentityMethod(), didWebIdentityMethod()],
        serviceDid: SERVICE_DID
      })
    ).toThrow(/identity method/u);

    expect(() =>
      buildInspectDocument({
        grantTypes: [oauthBearerGrantType(), oauthBearerGrantType()],
        identityMethods: [didWebIdentityMethod()],
        serviceDid: SERVICE_DID
      })
    ).toThrow(/grant type/u);
  });

  it("carries a custom grant type definition and its configuration", () => {
    const document = buildInspectDocument({
      grantTypes: [
        grantType("custom-type", { flavour: "vanilla" }, { grant: () => ({}), revoke: () => {} }),
        basicGrantType({ realm: "example" })
      ],
      identityMethods: [didWebIdentityMethod()],
      serviceDid: SERVICE_DID
    });

    expect(document.commands.grant_types).toContain("custom-type");
    expect(document.commands.grant_types_config?.["custom-type"]).toMatchObject({
      flavour: "vanilla"
    });
    expect(document.commands.grant_types_config?.["basic"]).toMatchObject({ realm: "example" });
  });
});

describe("JOSE-backed client assertion verifiers", () => {
  it("verifies an assertion with a configured key", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const verifier = createJwtClientAssertionVerifier({ currentDate: NOW, key: publicKey });
    const iat = Math.floor(NOW.getTime() / 1000);

    const assertion = await signClientAssertionJwt(
      { ...claims({ exp: iat + 300, iat, op: "status" }) },
      { alg: "EdDSA", key: privateKey }
    );

    await expect(
      verifier(assertion, {
        clientAssertion: assertion,
        command: "status",
        currentDate: NOW,
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      } as never)
    ).resolves.toMatchObject({ op: "status", sub: AGENT_DID });
  });

  it("resolves the Agent key through did:web", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyJwk = publicKey.export({ format: "jwk" });
    // did:web resolution has no injectable clock, so this assertion is signed for now.
    const iat = Math.floor(Date.now() / 1000);

    const assertion = await signClientAssertionJwt(
      { ...claims({ exp: iat + 300, iat, op: "status" }) },
      { alg: "EdDSA", key: privateKey }
    );

    const verifier = createDidWebClientAssertionVerifier({
      fetch: () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              id: AGENT_DID,
              verificationMethod: [
                { controller: AGENT_DID, id: AGENT_DID, publicKeyJwk, type: "JsonWebKey2020" }
              ]
            }),
            { headers: { "content-type": "application/json" }, status: 200 }
          )
        )
    });

    await expect(
      verifier(assertion, {
        clientAssertion: assertion,
        command: "status",
        currentDate: NOW,
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      } as never)
    ).resolves.toMatchObject({ sub: AGENT_DID });
  });
});
