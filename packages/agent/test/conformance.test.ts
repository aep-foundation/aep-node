import { generateKeyPairSync } from "node:crypto";

import { AEP_MEDIA_TYPE } from "@aep-foundation/core";
import type { InspectDocument, PlatformAgentIdentity } from "@aep-foundation/core";
import { describe, expect, it } from "vitest";

import {
  buildClientAssertionClaims,
  clientAssertionAuthenticationHeaders,
  createAepAgent,
  createInMemoryAgentIdentityStore,
  createInMemoryInspectCache,
  createInMemorySessionCredentialStore,
  createJwtClientAssertionSigner,
  createPlatformDelegatedSigner,
  createPlatformIdentityProvider,
  createRandomIdempotencyKeyProvider,
  credentialPresentationHeaders,
  enrollService,
  fetchProtectedResource,
  grantService,
  listPlatformIdentities,
  probeProtectedResource,
  protectedResourceAuthenticationHeaders,
  provisionPlatformIdentity,
  resolveServiceReference,
  revokeService,
  statusService
} from "../src/index.js";
import type {
  AepAgent,
  AepSessionCredentialRecord,
  AepServiceSession,
  InspectServiceResult,
  ResponseLike
} from "../src/index.js";

const SERVICE_DID = "did:web:api.example.com";
const AGENT_DID = "did:web:agent.example.com:agents:123";

const inspectDocumentFixture = {
  aep_version: "1.0",
  bindings: { supported: ["http"] },
  claims: { optional: [], preferred: [], required: [] },
  commands: {
    grant_types: ["oauth-bearer", "api-key"],
    grant_types_config: { "oauth-bearer": { supports_per_credential_revoke: "true" } },
    supported: ["enroll", "grant", "inspect", "revoke", "status"]
  },
  core: { signing_algorithms: ["EdDSA", "ES256"] },
  extensions: { supported: [] },
  http: { endpoint_base: "/aep/" },
  identity: { methods: ["did:web"] },
  service: { did: SERVICE_DID }
} satisfies InspectDocument;

function inspectResult(document: InspectDocument = inspectDocumentFixture): InspectServiceResult {
  return {
    document,
    inspectUrl: new URL("https://api.example.com/.well-known/aep"),
    commandUrl: (command) => new URL(`/aep/${command}`, "https://api.example.com")
  };
}

function headerMap(headers: Record<string, string>): { get(name: string): string | null } {
  const lower = new Map(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])
  );
  return { get: (name: string) => lower.get(name.toLowerCase()) ?? null };
}

function jsonResponse(
  body: unknown,
  options: { ok?: boolean; status?: number; headers?: Record<string, string> } = {}
): ResponseLike {
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    headers: headerMap({ "content-type": AEP_MEDIA_TYPE, ...(options.headers ?? {}) }),
    json: () => Promise.resolve(body)
  };
}

function platformIdentity(): PlatformAgentIdentity {
  return {
    agent_did: "did:web:platform.example.com:a:opaque",
    agent_identity_id: "pai_1",
    created_at: "2026-07-06T12:00:00Z",
    did_document_url: "https://platform.example.com/a/opaque/did.json",
    key_id: "did:web:platform.example.com:a:opaque",
    service_did: SERVICE_DID,
    signing_algorithms: ["ES256"],
    status: "active",
    updated_at: "2026-07-06T12:00:00Z"
  };
}

const platformDiscoveryDocument = {
  aep_version: "1.0",
  endpoints: {
    hosted_verification: "/v1/aep/verifications",
    lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
    list: "/v1/aep/agent-identities",
    provision: "/v1/aep/agent-identities",
    sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
  },
  http: { endpoint_base: "/v1/aep" },
  identity: {
    did_methods: ["did:web"],
    did_url_template: "https://platform.example.com/agents/{agent_did_id}/did.json"
  },
  platform: { did: "did:web:platform.example.com", hosted_verification: true, name: "Example" },
  signing: { algorithms: ["ES256"], default_lifetime_seconds: "300" }
};

function sessionCredentialRecord(
  overrides: Partial<AepSessionCredentialRecord> = {}
): AepSessionCredentialRecord {
  return {
    credential: {
      access_token: "access-token",
      credential_id: "cred-1",
      expires_at: "2999-05-28T12:00:00Z",
      scopes: [],
      token_type: "Bearer"
    },
    credentialId: "cred-1",
    expiresAt: "2999-05-28T12:00:00Z",
    grantType: "oauth-bearer",
    issuedAt: "2026-05-28T12:00:00Z",
    serviceDid: SERVICE_DID,
    ...overrides
  };
}

describe("client assertion construction guards", () => {
  const signer = () => Promise.resolve("header.payload.signature");

  it("rejects an operation that is not a registered assertion operation", () => {
    expect(() =>
      buildClientAssertionClaims({
        agentDid: AGENT_DID,
        command: "inspect" as Parameters<typeof buildClientAssertionClaims>[0]["command"],
        serviceDid: SERVICE_DID
      })
    ).toThrow("Unsupported authenticated command");
  });

  it("bounds the assertion lifetime to 1 through 300 seconds", () => {
    for (const ttlSeconds of [0, -1, 301, 1.5]) {
      expect(() =>
        buildClientAssertionClaims({
          agentDid: AGENT_DID,
          command: "status",
          serviceDid: SERVICE_DID,
          ttlSeconds
        })
      ).toThrow("between 1 and 300 seconds");
    }
  });

  it("requires a Service DID to build authentication headers", async () => {
    await expect(
      clientAssertionAuthenticationHeaders({ agentDid: AGENT_DID, signer })
    ).rejects.toThrow("require a service DID");
  });

  it("requires the protected-resource URI before minting a presentation", async () => {
    await expect(
      protectedResourceAuthenticationHeaders({
        agentDid: AGENT_DID,
        serviceDid: SERVICE_DID,
        signer
      })
    ).rejects.toThrow("requires the protected-resource URI");
  });
});

describe("signing algorithm selection", () => {
  const ed25519 = generateKeyPairSync("ed25519");
  const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" });

  async function sign(
    alg: string | undefined,
    advertised: string[]
  ): Promise<{ alg: unknown } | Error> {
    const expected = alg ?? (advertised.includes("EdDSA") ? "EdDSA" : advertised[0]);
    const signer = createJwtClientAssertionSigner({
      ...(alg === undefined ? {} : { alg }),
      key: expected === "EdDSA" ? ed25519.privateKey : p256.privateKey
    });
    const claims = buildClientAssertionClaims({
      agentDid: AGENT_DID,
      command: "status",
      serviceDid: SERVICE_DID
    });

    try {
      const jwt = await signer(claims, {
        command: "status",
        idempotencyKey: "key-1",
        serviceDid: SERVICE_DID,
        signingAlgorithms: advertised
      });
      const [header] = (typeof jwt === "string" ? jwt : "").split(".");
      return JSON.parse(Buffer.from(header ?? "", "base64url").toString("utf8")) as {
        alg: unknown;
      };
    } catch (error) {
      return error as Error;
    }
  }

  it("picks an advertised algorithm when none is configured", async () => {
    await expect(sign(undefined, ["EdDSA", "ES256"])).resolves.toMatchObject({ alg: "EdDSA" });
    await expect(sign("ES256", ["ES256", "EdDSA"])).resolves.toMatchObject({ alg: "ES256" });
  });

  it("refuses a configured algorithm the Service did not advertise", async () => {
    const result = await sign("ES384", ["EdDSA", "ES256"]);

    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).toContain("does not advertise the ES384");
  });

  it("accepts a configured algorithm the Service advertised", async () => {
    await expect(sign("EdDSA", ["EdDSA", "ES256"])).resolves.toMatchObject({ alg: "EdDSA" });
  });

  it("reports when the Service advertises no supported algorithm", async () => {
    const result = await sign(undefined, ["ES384", "RS256"]);

    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).toContain("does not advertise a supported JOSE");
  });
});

describe("credential presentation", () => {
  it("presents each built-in credential in its registered syntax", () => {
    expect(
      credentialPresentationHeaders({
        access_token: "opaque-token",
        credential_id: "c1",
        expires_at: "2999-01-01T00:00:00Z",
        scopes: [],
        token_type: "Bearer"
      })
    ).toEqual({ Authorization: "Bearer opaque-token" });

    expect(
      credentialPresentationHeaders({
        credential_id: "c1",
        expires_at: "2999-01-01T00:00:00Z",
        password: "secret",
        scopes: [],
        username: "agent"
      })
    ).toEqual({ Authorization: `Basic ${Buffer.from("agent:secret").toString("base64")}` });

    expect(
      credentialPresentationHeaders({
        api_key: "aep_live_example",
        credential_id: "c1",
        expires_at: "2999-01-01T00:00:00Z",
        header: "x-api-key",
        scopes: []
      })
    ).toEqual({ "x-api-key": "aep_live_example" });
  });

  it("uses the dedicated carrier for the credentials whose presentation allows it", () => {
    expect(
      credentialPresentationHeaders(
        {
          access_token: "opaque-token",
          credential_id: "c1",
          expires_at: "2999-01-01T00:00:00Z",
          scopes: [],
          token_type: "Bearer"
        },
        "dedicated"
      )
    ).toEqual({ "AEP-Authorization": "Bearer opaque-token" });
  });

  it("refuses an API-key field name that is not an HTTP field name", () => {
    for (const header of ["x-api-key\r\nX-Injected", "bad header", "", "x:api:key"]) {
      expect(() =>
        credentialPresentationHeaders({
          api_key: "aep_live_example",
          credential_id: "c1",
          expires_at: "2999-01-01T00:00:00Z",
          header,
          scopes: []
        })
      ).toThrow("not a valid HTTP field name");
    }
  });

  it("refuses an API-key value that could not be presented in a field", () => {
    for (const api_key of ["key with space", "key\r\nX-Injected: 1", "key,with,comma", ""]) {
      expect(() =>
        credentialPresentationHeaders({
          api_key,
          credential_id: "c1",
          expires_at: "2999-01-01T00:00:00Z",
          header: "x-api-key",
          scopes: []
        })
      ).toThrow(/not a valid API-key presentation|not a valid HTTP field name/);
    }
  });

  it("refuses a credential that is not a registered built-in profile", () => {
    expect(() =>
      credentialPresentationHeaders({
        unknown_credential: "value"
      } as unknown as Parameters<typeof credentialPresentationHeaders>[0])
    ).toThrow("Unsupported AEP built-in credential");
  });
});

describe("protected-resource challenge parsing", () => {
  async function challengeFrom(wwwAuthenticate: string): Promise<unknown> {
    const result = await probeProtectedResource({
      fetch: () =>
        Promise.resolve({
          ok: false,
          status: 401,
          headers: headerMap({ "www-authenticate": wwwAuthenticate }),
          json: () => Promise.resolve({})
        } as unknown as Response),
      url: "https://api.example.com/v1/orders"
    });

    return result.challenge;
  }

  it("reads a well-formed challenge", async () => {
    await expect(
      challengeFrom('AEP service_did="did:web:api.example.com",inspect="https://api.example.com/a"')
    ).resolves.toMatchObject({ serviceDid: "did:web:api.example.com" });
  });

  it("discards a challenge that repeats a parameter", async () => {
    await expect(
      challengeFrom(
        'AEP service_did="did:web:api.example.com",service_did="did:web:evil.example",' +
          'inspect="https://api.example.com/a"'
      )
    ).resolves.toBeUndefined();
  });

  it("discards a challenge missing a discovery parameter", async () => {
    await expect(
      challengeFrom('AEP service_did="did:web:api.example.com"')
    ).resolves.toBeUndefined();
    await expect(challengeFrom('AEP inspect="https://api.example.com/a"')).resolves.toBeUndefined();
  });

  it("discards a challenge whose Inspect URI is unusable", async () => {
    await expect(
      challengeFrom('AEP service_did="did:web:a.example",inspect="not a uri"')
    ).resolves.toBeUndefined();
    await expect(
      challengeFrom('AEP service_did="did:web:a.example",inspect="http://a.example/a"')
    ).resolves.toBeUndefined();
  });

  it("ignores a challenge that does not use the AEP scheme", async () => {
    await expect(challengeFrom('Bearer realm="api"')).resolves.toBeUndefined();
  });
});

describe("protected-resource redirect safety", () => {
  function redirectingAgent(): AepAgent {
    const session: AepServiceSession = {
      authenticationHeaders: () => Promise.resolve({ Authorization: "AEP a.b.c" }),
      enroll: () => Promise.reject(new Error("unused")),
      forgetCredential: () => Promise.reject(new Error("unused")),
      grant: () => Promise.reject(new Error("unused")),
      identity: () => Promise.reject(new Error("unused")),
      inspect: () => Promise.resolve(inspectResult()),
      openApiPolicy: () =>
        Promise.resolve({
          freshness: "fetched",
          methods: ["aep-jwt"],
          source: "openapi",
          state: "required"
        }),
      revoke: () => Promise.reject(new Error("unused")),
      status: () => Promise.reject(new Error("unused"))
    } as unknown as AepServiceSession;

    return { serviceSession: () => session };
  }

  async function followRedirect(location: string | null): Promise<Error> {
    const headers = location === null ? {} : { location };

    try {
      await fetchProtectedResource({
        agent: redirectingAgent(),
        fetch: () =>
          Promise.resolve(
            new Response(null, { status: 302, headers }) as unknown as ResponseLike
          ) as unknown as Promise<Response>,
        url: "https://api.example.com/v1/orders"
      });
      throw new Error("expected a rejection");
    } catch (error) {
      return error as Error;
    }
  }

  it("refuses a redirect that leaves HTTP", async () => {
    expect((await followRedirect("javascript:alert(1)")).message).toContain("changed scheme");
    expect((await followRedirect("data:text/plain,x")).message).toContain("changed scheme");
  });

  it("refuses a redirect that downgrades transport", async () => {
    expect((await followRedirect("http://api.example.com/v1/orders")).message).toContain(
      "downgraded transport"
    );
  });

  it("refuses a redirect that carries user information", async () => {
    expect((await followRedirect("https://user:pass@api.example.com/v1/orders")).message).toContain(
      "user information"
    );
  });

  it("refuses a redirect without a Location", async () => {
    expect((await followRedirect(null)).message).toContain("omitted Location");
  });

  it("enforces the redirect limit", async () => {
    let calls = 0;
    await expect(
      fetchProtectedResource({
        agent: redirectingAgent(),
        fetch: () => {
          calls += 1;
          return Promise.resolve(
            new Response(null, {
              status: 302,
              headers: { location: `https://api.example.com/v1/orders/${String(calls)}` }
            })
          );
        },
        maxRedirects: 2,
        url: "https://api.example.com/v1/orders"
      })
    ).rejects.toThrow("redirect limit exceeded");
  });

  it("refuses a request body that cannot be replayed", async () => {
    await expect(
      fetchProtectedResource({
        agent: redirectingAgent(),
        body: new ReadableStream(),
        url: "https://api.example.com/v1/orders"
      })
    ).rejects.toThrow("replayable request body");
  });
});

describe("command idempotency and grant-type guards", () => {
  const commandOptions = {
    agentDid: AGENT_DID,
    clientAssertion: "header.payload.signature",
    inspect: inspectResult(),
    serviceUrl: "https://api.example.com"
  };

  it("requires a non-empty idempotency key on every state-mutating command", async () => {
    for (const idempotencyKey of ["", "   "]) {
      await expect(enrollService({ ...commandOptions, idempotencyKey })).rejects.toThrow(
        "non-empty idempotency key"
      );
      await expect(
        grantService({ ...commandOptions, grantType: "oauth-bearer", idempotencyKey })
      ).rejects.toThrow("non-empty idempotency key");
      await expect(
        revokeService({ ...commandOptions, grantType: "oauth-bearer", idempotencyKey })
      ).rejects.toThrow("non-empty idempotency key");
    }
  });

  it("refuses a grant type the Service does not advertise", async () => {
    await expect(
      grantService({ ...commandOptions, grantType: "basic", idempotencyKey: "key-1" })
    ).rejects.toThrow("does not advertise the basic grant type");

    await expect(
      revokeService({ ...commandOptions, grantType: "basic", idempotencyKey: "key-1" })
    ).rejects.toThrow("does not advertise the basic grant type");
  });

  it("refuses any grant type when the Service advertises none", async () => {
    const { grant_types: _omitted, ...commandsWithoutGrantTypes } = inspectDocumentFixture.commands;
    const withoutGrantTypes = inspectResult({
      ...inspectDocumentFixture,
      commands: commandsWithoutGrantTypes
    });

    await expect(
      grantService({
        ...commandOptions,
        grantType: "oauth-bearer",
        idempotencyKey: "key-1",
        inspect: withoutGrantTypes
      })
    ).rejects.toThrow("does not advertise the oauth-bearer grant type");

    await expect(
      revokeService({
        ...commandOptions,
        grantType: "oauth-bearer",
        idempotencyKey: "key-1",
        inspect: withoutGrantTypes
      })
    ).rejects.toThrow("does not advertise the oauth-bearer grant type");
  });

  it("allows all-grant-types Revoke without naming a grant type", async () => {
    const calls: Array<RequestInit["body"]> = [];
    const result = await revokeService({
      ...commandOptions,
      allGrantTypes: true,
      fetch: (_input, init) => {
        calls.push(init?.body);
        return Promise.resolve(jsonResponse({}));
      },
      idempotencyKey: "key-1"
    });

    expect(result.status).toBe(200);
    expect(JSON.parse(bodyText(calls[0]))).toEqual({ all_grant_types: "true" });
  });

  it("refuses per-credential Revoke the Service does not advertise", async () => {
    await expect(
      revokeService({
        ...commandOptions,
        credentialId: "cred-1",
        grantType: "api-key",
        idempotencyKey: "key-1"
      })
    ).rejects.toThrow("does not advertise per-credential Revoke");
  });
});

describe("command cancellation", () => {
  const commandOptions = {
    agentDid: AGENT_DID,
    clientAssertion: "header.payload.signature",
    inspect: inspectResult(),
    serviceUrl: "https://api.example.com"
  };

  it("forwards the abort signal to every command request", async () => {
    const seen: Array<AbortSignal | undefined> = [];
    const controller = new AbortController();
    const fetchImpl = (_input: URL | string, init?: RequestInit): Promise<ResponseLike> => {
      seen.push(init?.signal ?? undefined);
      return Promise.resolve(jsonResponse({ status: "active" }));
    };

    await enrollService({
      ...commandOptions,
      fetch: fetchImpl,
      idempotencyKey: "key-1",
      signal: controller.signal
    });
    await statusService({ ...commandOptions, fetch: fetchImpl, signal: controller.signal });
    await revokeService({
      ...commandOptions,
      allGrantTypes: true,
      fetch: (input, init) => {
        seen.push(init?.signal ?? undefined);
        void input;
        return Promise.resolve(jsonResponse({}));
      },
      idempotencyKey: "key-1",
      signal: controller.signal
    });

    expect(seen).toHaveLength(3);
    for (const signal of seen) {
      expect(signal).toBe(controller.signal);
    }
  });
});

describe("in-memory session credential store", () => {
  it("returns the first usable credential for a Service and skips the rest", async () => {
    const store = createInMemorySessionCredentialStore([
      sessionCredentialRecord({
        credentialId: "other-service",
        serviceDid: "did:web:other.example"
      }),
      sessionCredentialRecord({ credentialId: "expired", expiresAt: "2000-01-01T00:00:00Z" }),
      sessionCredentialRecord({ credentialId: "unparsable", expiresAt: "not-a-date" }),
      sessionCredentialRecord({ credentialId: "usable" })
    ]);

    const usable = await store.findUsableCredential(SERVICE_DID, new Date("2026-01-01T00:00:00Z"));

    expect(usable?.credentialId).toBe("usable");
  });

  it("reports no usable credential when every record has lapsed", async () => {
    const store = createInMemorySessionCredentialStore([
      sessionCredentialRecord({ credentialId: "expired", expiresAt: "2000-01-01T00:00:00Z" })
    ]);

    expect(
      await store.findUsableCredential(SERVICE_DID, new Date("2026-01-01T00:00:00Z"))
    ).toBeUndefined();
  });

  it("falls back to the credential's own expiry when the record omits one", async () => {
    const record = sessionCredentialRecord({ credentialId: "record-without-expiry" });
    delete record.expiresAt;
    const store = createInMemorySessionCredentialStore([record]);

    expect(await store.findUsableCredential(SERVICE_DID)).toMatchObject({
      credentialId: "record-without-expiry"
    });
  });

  it("discards a record whose expiry cannot be determined", async () => {
    const record = sessionCredentialRecord({ credentialId: "no-expiry-anywhere" });
    delete record.expiresAt;
    record.credential = { ...(record.credential as Record<string, unknown>), expires_at: "later" };
    const store = createInMemorySessionCredentialStore([record]);

    expect(await store.findUsableCredential(SERVICE_DID)).toBeUndefined();
    expect(await store.listCredentials(SERVICE_DID)).toEqual([]);
  });

  it("finds, lists, and deletes credentials by identifier", async () => {
    const store = createInMemorySessionCredentialStore();
    await store.saveCredential(sessionCredentialRecord());

    expect(await store.findCredential(SERVICE_DID, "cred-1")).toMatchObject({
      credentialId: "cred-1"
    });
    expect(await store.listCredentials(SERVICE_DID)).toHaveLength(1);

    await store.deleteCredential(SERVICE_DID, "cred-1");

    expect(await store.findCredential(SERVICE_DID, "cred-1")).toBeUndefined();
    expect(await store.listCredentials(SERVICE_DID)).toEqual([]);
  });
});

describe("in-memory identity store and key provider", () => {
  it("round-trips an Agent identity and clones it on the way out", async () => {
    const store = createInMemoryAgentIdentityStore();
    const identity = {
      agentDid: AGENT_DID,
      identityKind: "sovereign" as const,
      serviceDid: SERVICE_DID,
      signingAlgorithms: ["EdDSA"]
    };

    expect(await store.findByServiceDid(SERVICE_DID)).toBeUndefined();
    const saved = await store.saveIdentity(identity);
    expect(saved).not.toBe(identity);

    const found = await store.findByServiceDid(SERVICE_DID);
    expect(found).toMatchObject({ agentDid: AGENT_DID });
    expect(found).not.toBe(saved);
  });

  it("seeds from records", async () => {
    const store = createInMemoryAgentIdentityStore([
      {
        agentDid: AGENT_DID,
        identityKind: "sovereign",
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      }
    ]);

    expect(await store.findByServiceDid(SERVICE_DID)).toMatchObject({ agentDid: AGENT_DID });
  });

  it("produces a distinct idempotency key per operation", async () => {
    const provider = createRandomIdempotencyKeyProvider();
    const operation = {
      command: "enroll" as const,
      serviceDid: SERVICE_DID,
      serviceUrl: "https://api.example.com"
    };

    const first = await provider.createKey(operation);
    const second = await provider.createKey(operation);

    expect(first).not.toBe(second);
    expect(first.length).toBeGreaterThan(0);

    const fixed = createRandomIdempotencyKeyProvider(() => "fixed-key");
    expect(await fixed.createKey(operation)).toBe("fixed-key");
  });
});

describe("in-memory Inspect cache", () => {
  it("seeds from records and honors no-cache and unparsable timestamps", async () => {
    const seeded = {
      ...inspectResult(),
      cachedAt: new Date().toISOString()
    };
    const cache = createInMemoryInspectCache([
      { serviceUrl: "https://api.example.com/", result: seeded }
    ]);

    expect(await cache.get("https://api.example.com/")).toMatchObject({
      cachedAt: seeded.cachedAt
    });

    await cache.set("https://api.example.com/", { ...seeded, cachedAt: "not-a-date" });
    expect(await cache.get("https://api.example.com/")).toMatchObject({ cachedAt: "not-a-date" });

    await cache.delete("https://api.example.com/");
    expect(await cache.get("https://api.example.com/")).toBeUndefined();
  });
});

describe("Platform client requests", () => {
  async function withFetch<T>(
    handler: (input: URL | string, init?: RequestInit) => Promise<unknown>,
    run: () => Promise<T>
  ): Promise<T> {
    const previous = globalThis.fetch;
    globalThis.fetch = handler as unknown as typeof fetch;

    try {
      return await run();
    } finally {
      globalThis.fetch = previous;
    }
  }

  function discoveryOr(
    handler: (input: URL | string, init?: RequestInit) => Promise<unknown>
  ): (input: URL | string, init?: RequestInit) => Promise<unknown> {
    return (input, init) => {
      if (String(input).includes("/.well-known/aep-platform")) {
        return Promise.resolve(
          new Response(JSON.stringify(platformDiscoveryDocument), {
            headers: { "content-type": AEP_MEDIA_TYPE }
          })
        );
      }
      return handler(input, init);
    };
  }

  it("provisions a Service-scoped identity with an idempotency key", async () => {
    const calls: Array<{ init: RequestInit | undefined; url: string }> = [];
    const result = await withFetch(
      discoveryOr((input, init) => {
        calls.push({ init, url: String(input) });
        return Promise.resolve(jsonResponse(platformIdentity()));
      }),
      () =>
        provisionPlatformIdentity({
          authorization: "Bearer platform-token",
          idempotencyKey: "provision-key",
          platformUrl: "https://platform.example.com",
          serviceDid: SERVICE_DID
        })
    );

    expect(result.body.agent_identity_id).toBe("pai_1");
    const provision = calls.find((call) => call.url.endsWith("/v1/aep/agent-identities"));
    expect(provision).toBeDefined();
    expect(headerValue(provision?.init, "Idempotency-Key")).toBe("provision-key");
    expect(JSON.parse(bodyText(provision?.init?.body))).toEqual({ service_did: SERVICE_DID });
  });

  it("lists identities with every supported query parameter", async () => {
    let listUrl = "";
    const result = await withFetch(
      discoveryOr((input) => {
        listUrl = String(input);
        return Promise.resolve(
          jsonResponse({ count: "1", data: [platformIdentity()], total: "1" })
        );
      }),
      () =>
        listPlatformIdentities({
          authorization: "Bearer platform-token",
          descending: true,
          limit: 10,
          offset: 5,
          platformUrl: "https://platform.example.com",
          serviceDid: SERVICE_DID,
          status: "active"
        })
    );

    expect(result.body.count).toBe("1");
    const query = new URL(listUrl).searchParams;
    expect(query.get("descending")).toBe("true");
    expect(query.get("limit")).toBe("10");
    expect(query.get("offset")).toBe("5");
    expect(query.get("service_did")).toBe(SERVICE_DID);
    expect(query.get("status")).toBe("active");
  });

  it("signs through the Platform and returns the assertion", async () => {
    let signBody: unknown;
    const signed = await withFetch(
      discoveryOr((_input, init) => {
        signBody = JSON.parse(bodyText(init?.body));
        return Promise.resolve(
          jsonResponse({
            agent_did: platformIdentity().agent_did,
            client_assertion: "header.payload.signature",
            expires_at: "2026-07-06T12:05:00Z",
            issued_at: "2026-07-06T12:00:00Z",
            jti: "assertion-1",
            service_did: SERVICE_DID,
            status: "completed"
          })
        );
      }),
      () => {
        const signer = createPlatformDelegatedSigner({
          authorization: "Bearer platform-token",
          identity: platformIdentity(),
          platformUrl: "https://platform.example.com"
        });
        const claims = buildClientAssertionClaims({
          agentDid: platformIdentity().agent_did,
          command: "enroll",
          serviceDid: SERVICE_DID
        });

        return Promise.resolve(
          signer(claims, {
            command: "enroll",
            idempotencyKey: "sign-key",
            serviceDid: SERVICE_DID,
            signingAlgorithms: ["ES256"]
          })
        );
      }
    );

    expect(signed).toMatchObject({
      clientAssertion: "header.payload.signature",
      status: "completed"
    });
    expect(signBody).toMatchObject({ op: "enroll", service_did: SERVICE_DID });
  });

  it("refuses to sign for a sovereign identity", async () => {
    const provider = createPlatformIdentityProvider({
      authorization: "Bearer platform-token",
      platformUrl: "https://platform.example.com"
    });

    await expect(
      provider.signerFor({
        agentDid: AGENT_DID,
        identityKind: "sovereign",
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["EdDSA"]
      })
    ).rejects.toThrow("cannot sign for a sovereign identity");
  });
});

describe("Service reference normalization", () => {
  it("reduces a reference to its origin", () => {
    expect(
      String(resolveServiceReference("https://api.example.com/deep/path?query#fragment"))
    ).toBe("https://api.example.com/");
    expect(String(resolveServiceReference(new URL("https://api.example.com/x")))).toBe(
      "https://api.example.com/"
    );
  });
});

describe("global fetch requirement", () => {
  it("reports when the runtime supplies no fetch", async () => {
    const previous = globalThis.fetch;

    try {
      (globalThis as { fetch?: unknown }).fetch = undefined;
      await expect(
        enrollService({
          agentDid: AGENT_DID,
          clientAssertion: "a.b.c",
          idempotencyKey: "key-1",
          inspect: inspectResult(),
          serviceUrl: "https://api.example.com"
        })
      ).rejects.toThrow(/fetch/i);
    } finally {
      globalThis.fetch = previous;
    }
  });
});

describe("agent session wiring", () => {
  it("builds a session for a Service reference", () => {
    const agent = createAepAgent({
      agentDid: AGENT_DID,
      clientAssertionSigner: () => Promise.resolve("header.payload.signature")
    } as never);

    expect(agent.serviceSession({ serviceUrl: "https://api.example.com" })).toBeDefined();
  });
});

function bodyText(body: RequestInit["body"]): string {
  return typeof body === "string" ? body : "";
}

function headerValue(init: RequestInit | undefined, name: string): string | undefined {
  const headers = init?.headers;

  if (headers === undefined) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (Array.isArray(headers)) {
    return headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  }

  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
  return entry?.[1];
}
