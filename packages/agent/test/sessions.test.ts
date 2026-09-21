import { AEP_MEDIA_TYPE } from "@aep-foundation/core";
import { describe, expect, it } from "vitest";

import {
  createAepAgent,
  createInMemoryInspectCache,
  createInMemoryPublicDocumentCache,
  createInMemorySessionCredentialStore,
  discoverPlatform,
  fetchAepPublicDocument,
  fetchProtectedResource,
  inspectService,
  probeProtectedResource
} from "../src/index.js";
import type {
  AepAgent,
  AepServiceSession,
  AepSessionCredentialRecord,
  InspectServiceResult,
  ResponseLike
} from "../src/index.js";

const SERVICE_DID = "did:web:api.example.com";
const AGENT_DID = "did:web:agent.example.com:agents:123";

const inspectDocumentFixture = {
  aep_version: "1.0",
  bindings: { supported: ["http"] },
  commands: {
    grant_types: ["oauth-bearer"],
    supported: ["enroll", "grant", "inspect", "revoke", "status"]
  },
  core: { signing_algorithms: ["EdDSA", "ES256"] },
  http: { endpoint_base: "/aep/" },
  identity: { methods: ["did:web"] },
  service: { did: SERVICE_DID }
};

function inspectResult(): InspectServiceResult {
  return {
    document: inspectDocumentFixture,
    inspectUrl: new URL("https://api.example.com/.well-known/aep"),
    commandUrl: (command: string) => new URL(`/aep/${command}`, "https://api.example.com")
  };
}

function json(body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": AEP_MEDIA_TYPE, ...headers }
  });
}

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

describe("Inspect caching failure paths", () => {
  it("evicts both cached redirect locations when the final document has another Service DID", async () => {
    const cache = createInMemoryPublicDocumentCache();
    const original = "https://api.example.com/.well-known/aep";
    const redirected = "https://api.example.com/discovery";
    await expect(
      inspectService({
        serviceUrl: "https://api.example.com",
        publicDocumentCache: cache,
        clock: () => new Date("2026-01-01T00:00:00Z"),
        maxResponseBytes: 4096,
        timeoutMs: 1000,
        signal: new AbortController().signal,
        fetch: (input) =>
          Promise.resolve(
            String(input) === original
              ? new Response(null, { status: 302, headers: { location: redirected } })
              : json(
                  { ...inspectDocumentFixture, service: { did: "did:web:other.example" } },
                  {
                    "cache-control": "max-age=300",
                    etag: '"v1"',
                    "last-modified": "Thu, 01 Jan 2026 00:00:00 GMT"
                  }
                )
          )
      })
    ).rejects.toMatchObject({ code: "service_identity_mismatch" });
    expect(await cache.get("inspect", original)).toBeUndefined();
    expect(await cache.get("inspect", redirected)).toBeUndefined();
  });

  it("honors no-store and updated validators on a 304 response in the Inspect cache", async () => {
    const lastModified = "Thu, 01 Jan 2026 00:00:00 GMT";
    const cache = createInMemoryInspectCache([
      {
        serviceUrl: "https://api.example.com/",
        result: {
          ...inspectResult(),
          cachedAt: "2026-01-01T00:00:00Z",
          cacheControl: "no-cache",
          etag: '"v1"',
          lastModified
        }
      }
    ]);
    const result = await inspectService({
      serviceUrl: "https://api.example.com",
      inspectCache: cache,
      fetch: (_input, init) => {
        expect(new Headers(init?.headers).get("if-modified-since")).toBe(lastModified);
        expect(new Headers(init?.headers).get("if-none-match")).toBe('"v1"');
        return Promise.resolve(
          new Response(null, {
            status: 304,
            headers: {
              "cache-control": "no-store",
              etag: '"v2"',
              "last-modified": lastModified
            }
          })
        );
      }
    });
    expect(result).toMatchObject({ cacheControl: "no-store", etag: '"v2"', lastModified });
    expect(await cache.get("https://api.example.com/")).toBeUndefined();
  });

  it("evicts a cached document that no longer satisfies the origin binding", async () => {
    const cache = createInMemoryInspectCache([
      {
        serviceUrl: "https://api.example.com/",
        result: {
          ...inspectResult(),
          document: { ...inspectDocumentFixture, service: { did: "did:web:other.example" } },
          cachedAt: new Date().toISOString()
        }
      }
    ]);

    await expect(
      inspectService({ inspectCache: cache, serviceUrl: "https://api.example.com" })
    ).rejects.toThrow(/Service DID/);

    expect(await cache.get("https://api.example.com/")).toBeUndefined();
  });

  it("reports a 304 that arrives with no cached representation", async () => {
    await expect(
      withFetch(
        () =>
          Promise.resolve({
            ok: false,
            status: 304,
            headers: new Headers(),
            json: () => Promise.resolve({})
          }),
        () => inspectService({ serviceUrl: "https://api.example.com" })
      )
    ).rejects.toThrow(/304/);
  });

  it("evicts the public-document cache entry when the document stops validating", async () => {
    const cache = createInMemoryPublicDocumentCache();

    await expect(
      withFetch(
        () => Promise.resolve(json({ ...inspectDocumentFixture, aep_version: "2.0" })),
        () =>
          inspectService({
            publicDocumentCache: cache,
            serviceUrl: "https://api.example.com"
          })
      )
    ).rejects.toThrow();

    expect(await cache.get("inspect", "https://api.example.com/.well-known/aep")).toBeUndefined();
  });

  it("wraps a transport failure from the public-document path", async () => {
    const cache = createInMemoryPublicDocumentCache();

    await expect(
      withFetch(
        () => Promise.reject(new Error("connection reset")),
        () => inspectService({ publicDocumentCache: cache, serviceUrl: "https://api.example.com" })
      )
    ).rejects.toThrow("connection reset");
  });

  it("does not retain a no-store Inspect document", async () => {
    const cache = createInMemoryInspectCache();

    await withFetch(
      () => Promise.resolve(json(inspectDocumentFixture, { "cache-control": "no-store" })),
      () => inspectService({ inspectCache: cache, serviceUrl: "https://api.example.com" })
    );

    expect(await cache.get("https://api.example.com/")).toBeUndefined();
  });

  it("builds command URLs from the validated document", async () => {
    const cache = createInMemoryPublicDocumentCache();
    const result = await withFetch(
      () => Promise.resolve(json(inspectDocumentFixture)),
      () => inspectService({ publicDocumentCache: cache, serviceUrl: "https://api.example.com" })
    );

    expect(String(result.commandUrl("enroll"))).toBe("https://api.example.com/aep/enroll");
  });

  it("reports a response body it cannot read", async () => {
    await expect(
      withFetch(
        () =>
          Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ "content-type": AEP_MEDIA_TYPE }),
            json: () => Promise.reject(new Error("stream closed"))
          }),
        () => inspectService({ serviceUrl: "https://api.example.com" })
      )
    ).rejects.toThrow();
  });
});

describe("Inspect cache freshness", () => {
  it("uses the default five-minute lifetime when Cache-Control is absent", async () => {
    const cache = createInMemoryInspectCache([
      {
        serviceUrl: "https://api.example.com/",
        result: {
          ...inspectResult(),
          cachedAt: "2026-01-01T00:00:00Z"
        }
      }
    ]);
    let requests = 0;
    const fetch = () => {
      requests++;
      return Promise.resolve(json(inspectDocumentFixture));
    };
    await inspectService({
      serviceUrl: "https://api.example.com",
      inspectCache: cache,
      fetch,
      clock: () => new Date("2026-01-01T00:04:59Z")
    });
    expect(requests).toBe(0);
    await inspectService({
      serviceUrl: "https://api.example.com",
      inspectCache: cache,
      fetch,
      clock: () => new Date("2026-01-01T00:05:00Z")
    });
    expect(requests).toBe(1);
  });

  it("refetches when the cached timestamp cannot be parsed", async () => {
    const cache = createInMemoryInspectCache([
      {
        serviceUrl: "https://api.example.com/",
        result: { ...inspectResult(), cachedAt: "not-a-date" }
      }
    ]);
    let calls = 0;

    await withFetch(
      () => {
        calls += 1;
        return Promise.resolve(json(inspectDocumentFixture));
      },
      () => inspectService({ inspectCache: cache, serviceUrl: "https://api.example.com" })
    );

    expect(calls).toBe(1);
  });

  it("refetches a no-cache document and ignores a blank directive", async () => {
    const cache = createInMemoryInspectCache([
      {
        serviceUrl: "https://api.example.com/",
        result: {
          ...inspectResult(),
          cacheControl: "no-cache, , max-age=300",
          cachedAt: new Date().toISOString()
        }
      }
    ]);
    let calls = 0;

    await withFetch(
      () => {
        calls += 1;
        return Promise.resolve(json(inspectDocumentFixture));
      },
      () => inspectService({ inspectCache: cache, serviceUrl: "https://api.example.com" })
    );

    expect(calls).toBe(1);
  });
});

describe("protected-resource fetch outcomes", () => {
  function agentFor(session: Partial<AepServiceSession>): AepAgent {
    const unavailable = (): Promise<never> => Promise.reject(new Error("unused"));
    const full = {
      authenticationHeaders: () => Promise.resolve({ Authorization: "AEP a.b.c" }),
      enroll: unavailable,
      forgetCredential: unavailable,
      grant: unavailable,
      identity: unavailable,
      inspect: () => Promise.resolve(inspectResult()),
      openApiPolicy: () =>
        Promise.resolve({
          freshness: "fetched",
          methods: [],
          source: "openapi",
          state: "fallback"
        }),
      revoke: unavailable,
      status: unavailable,
      ...session
    } as unknown as AepServiceSession;

    return { serviceSession: () => full };
  }

  it("returns an unrelated response without attempting authentication", async () => {
    const response = await fetchProtectedResource({
      agent: agentFor({}),
      fetch: () => Promise.resolve(new Response("ok", { status: 200 })),
      url: "https://api.example.com/v1/orders"
    });

    expect(response.status).toBe(200);
  });

  it("returns an unrelated 401 that carries no AEP challenge", async () => {
    const response = await fetchProtectedResource({
      agent: agentFor({}),
      fetch: () =>
        Promise.resolve(
          new Response(null, { status: 401, headers: { "www-authenticate": 'Basic realm="x"' } })
        ),
      url: "https://api.example.com/v1/orders"
    });

    expect(response.status).toBe(401);
  });

  it("returns the anonymous response when the Service advertises no method", async () => {
    const response = await fetchProtectedResource({
      agent: agentFor({
        inspect: () =>
          Promise.resolve({
            ...inspectResult(),
            document: { ...inspectDocumentFixture, authentication: undefined }
          } as never)
      }),
      fetch: () =>
        Promise.resolve(
          new Response(null, {
            status: 401,
            headers: {
              "www-authenticate":
                'AEP service_did="did:web:api.example.com",inspect="https://api.example.com/.well-known/aep"'
            }
          })
        ),
      url: "https://api.example.com/v1/orders"
    });

    expect(response.status).toBe(401);
  });

  it("refuses a challenge whose Inspect URI names another origin", async () => {
    await expect(
      fetchProtectedResource({
        agent: agentFor({}),
        fetch: () =>
          Promise.resolve(
            new Response(null, {
              status: 401,
              headers: {
                "www-authenticate":
                  'AEP service_did="did:web:api.example.com",inspect="https://cdn.example.net/a"'
              }
            })
          ) as never,
        url: "https://api.example.com/v1/orders"
      })
    ).rejects.toThrow("Inspect URI changed origin");
  });

  it("refuses a challenge whose Service DID does not match Inspect", async () => {
    await expect(
      fetchProtectedResource({
        agent: agentFor({}),
        fetch: () =>
          Promise.resolve(
            new Response(null, {
              status: 401,
              headers: {
                "www-authenticate":
                  'AEP service_did="did:web:other.example",inspect="https://api.example.com/.well-known/aep"'
              }
            })
          ) as never,
        url: "https://api.example.com/v1/orders"
      })
    ).rejects.toThrow("did not match Inspect");
  });

  it("continues when the OpenAPI policy lookup fails", async () => {
    const response = await fetchProtectedResource({
      agent: agentFor({ openApiPolicy: () => Promise.reject(new Error("openapi unavailable")) }),
      fetch: () => Promise.resolve(new Response("ok", { status: 200 })),
      url: "https://api.example.com/v1/orders"
    });

    expect(response.status).toBe(200);
  });

  it("reports when a required policy supplies no usable method", async () => {
    await expect(
      fetchProtectedResource({
        agent: agentFor({
          openApiPolicy: () =>
            Promise.resolve({
              freshness: "fetched",
              methods: [],
              source: "openapi",
              state: "required"
            })
        }),
        fetch: () => Promise.resolve(new Response("ok", { status: 200 })) as never,
        url: "https://api.example.com/v1/orders"
      })
    ).rejects.toThrow("supplies no usable AEP method");
  });

  it("obtains a credential and retries when the first presentation cannot be built", async () => {
    let grants = 0;
    let attempts = 0;
    const response = await fetchProtectedResource({
      agent: agentFor({
        authenticationHeaders: () => {
          attempts += 1;
          if (attempts === 1) return Promise.reject(new Error("no credential yet"));
          return Promise.resolve({ Authorization: "Bearer token" });
        },
        grant: () => {
          grants += 1;
          return Promise.resolve({ credentialId: "cred-1" } as never);
        },
        inspect: () =>
          Promise.resolve({
            ...inspectResult(),
            document: {
              ...inspectDocumentFixture,
              authentication: { methods: ["oauth-bearer"] }
            }
          } as never),
        openApiPolicy: () =>
          Promise.resolve({
            freshness: "fetched",
            methods: [],
            source: "openapi",
            state: "fallback"
          })
      }),
      fetch: (_input, init) =>
        Promise.resolve(
          new Response(
            null,
            init?.headers === undefined
              ? {
                  status: 401,
                  headers: {
                    "www-authenticate":
                      'AEP service_did="did:web:api.example.com",inspect="https://api.example.com/.well-known/aep"'
                  }
                }
              : { status: 200 }
          )
        ),
      url: "https://api.example.com/v1/orders"
    });

    expect(grants).toBe(1);
    expect(response.status).toBe(200);
  });

  it("classifies a plain probe response", async () => {
    const result = await probeProtectedResource({
      fetch: () => Promise.resolve(new Response("ok", { status: 200 })),
      url: "https://api.example.com/v1/orders"
    });

    expect(result.classification).toBe("success");

    const forbidden = await probeProtectedResource({
      fetch: () => Promise.resolve(new Response(null, { status: 403 })),
      url: "https://api.example.com/v1/orders"
    });

    expect(forbidden.classification).toBe("http-response");
  });
});

describe("session credential lifecycle", () => {
  function credential(credentialId: string): AepSessionCredentialRecord {
    return {
      credential: {
        access_token: "token",
        credential_id: credentialId,
        expires_at: "2999-01-01T00:00:00Z",
        scopes: [],
        token_type: "Bearer"
      },
      credentialId,
      expiresAt: "2999-01-01T00:00:00Z",
      grantType: "oauth-bearer",
      issuedAt: "2026-01-01T00:00:00Z",
      serviceDid: SERVICE_DID
    };
  }

  it("forgets a stored credential through the session", async () => {
    const credentialStore = createInMemorySessionCredentialStore([credential("cred-1")]);
    const agent = createAepAgent({
      agentDid: AGENT_DID,
      clientAssertionSigner: () => Promise.resolve("a.b.c"),
      credentialStore
    } as never);

    await withFetch(
      () => Promise.resolve(json(inspectDocumentFixture)),
      async () => {
        const session = agent.serviceSession({ serviceUrl: "https://api.example.com" });
        await session.forgetCredential("cred-1");
      }
    );

    expect(await credentialStore.findCredential(SERVICE_DID, "cred-1")).toBeUndefined();
  });

  it("shares one Inspect request between concurrent session callers", async () => {
    let calls = 0;
    const agent = createAepAgent({
      agentDid: AGENT_DID,
      clientAssertionSigner: () => Promise.resolve("a.b.c")
    } as never);

    await withFetch(
      () => {
        calls += 1;
        return Promise.resolve(json(inspectDocumentFixture));
      },
      async () => {
        const session = agent.serviceSession({ serviceUrl: "https://api.example.com" });
        await Promise.all([session.inspect(), session.inspect(), session.inspect()]);
      }
    );

    expect(calls).toBe(1);
  });
});

describe("session Inspect freshness", () => {
  it.each(["no-store", "no-cache", "max-age=0", "max-age=300"])(
    "honors %s across sequential calls",
    async (cacheControl) => {
      let calls = 0;
      const agent = createAepAgent({
        identityProvider: {
          getOrCreateIdentity: () => {
            throw new Error("unused");
          },
          signerFor: () => {
            throw new Error("unused");
          }
        },
        fetch: () => {
          calls += 1;
          return Promise.resolve(json(inspectDocumentFixture, { "cache-control": cacheControl }));
        }
      });
      const session = agent.serviceSession({ serviceUrl: "https://api.example.com" });
      await session.inspect();
      await session.inspect();
      expect(calls).toBe(cacheControl === "max-age=300" ? 1 : 2);
    }
  );

  it("retries Inspect after a failed fetch", async () => {
    let calls = 0;
    const agent = createAepAgent({
      identityProvider: {
        getOrCreateIdentity: () => {
          throw new Error("unused");
        },
        signerFor: () => {
          throw new Error("unused");
        }
      },
      fetch: () => {
        calls += 1;
        if (calls === 1) return Promise.reject(new Error("offline"));
        return Promise.resolve(json(inspectDocumentFixture));
      }
    });
    const session = agent.serviceSession({ serviceUrl: "https://api.example.com" });
    await expect(session.inspect()).rejects.toThrow("offline");
    await expect(session.inspect()).resolves.toHaveProperty("document");
    expect(calls).toBe(2);
  });
});

describe("public document transport bounds", () => {
  it("reports a non-streaming body that exceeds the bound", async () => {
    await expect(
      fetchAepPublicDocument({
        accept: AEP_MEDIA_TYPE,
        fetch: () =>
          Promise.resolve({
            ok: true,
            status: 200,
            headers: { get: () => null },
            json: () => Promise.resolve({ padding: "x".repeat(64) })
          }) as never,
        maxResponseBytes: 8,
        namespace: "inspect",
        parse: (value: unknown) => value,
        url: "https://api.example.com/.well-known/aep"
      })
    ).rejects.toThrow("too large");
  });

  it("rejects a media type whose parameter has no name", async () => {
    await expect(
      fetchAepPublicDocument({
        accept: AEP_MEDIA_TYPE,
        acceptedMediaTypes: [AEP_MEDIA_TYPE],
        fetch: () =>
          Promise.resolve(
            new Response(JSON.stringify({}), {
              headers: { "content-type": "application/aep+json;=value" }
            })
          ) as never,
        namespace: "inspect",
        parse: (value: unknown) => value,
        url: "https://api.example.com/.well-known/aep"
      })
    ).rejects.toThrow("media type is invalid");
  });
});

describe("Platform discovery endpoint resolution", () => {
  it("reports an endpoint the discovery document omits", async () => {
    const discovery = await withFetch(
      () =>
        Promise.resolve(
          json({
            aep_version: "1.0",
            endpoints: {
              lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
              list: "/v1/aep/agent-identities",
              provision: "/v1/aep/agent-identities",
              sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
            },
            http: { endpoint_base: "/v1/aep" },
            identity: {
              did_methods: ["did:web"],
              did_url_template: "https://platform.example.com/a/{agent_did_id}/did.json"
            },
            platform: { hosted_verification: false, name: "Example" },
            signing: { algorithms: ["ES256"], default_lifetime_seconds: "300" }
          })
        ),
      () => discoverPlatform({ platformUrl: "https://platform.example.com" })
    );

    expect(() => discovery.endpointUrl("hosted_verification")).toThrow("does not advertise");
    expect(String(discovery.endpointUrl("provision"))).toContain("/v1/aep/agent-identities");
  });
});

describe("Grant response shape", () => {
  it("rejects a Grant response that is not an object", async () => {
    const agent = createAepAgent({
      agentDid: AGENT_DID,
      clientAssertionSigner: () => Promise.resolve("a.b.c"),
      idempotencyKeyProvider: { createKey: () => "key-1" }
    } as never);

    await expect(
      withFetch(
        (input) =>
          String(input).includes("/.well-known/aep")
            ? Promise.resolve(json(inspectDocumentFixture))
            : Promise.resolve(json("not-an-object")),
        () =>
          agent
            .serviceSession({ serviceUrl: "https://api.example.com" })
            .grant({ grantType: "oauth-bearer" })
      )
    ).rejects.toThrow();
  });
});

describe("resource fetch without a global fetch", () => {
  it("reports the missing runtime capability", async () => {
    const previous = globalThis.fetch;

    try {
      (globalThis as { fetch?: unknown }).fetch = undefined;
      await expect(
        probeProtectedResource({ url: "https://api.example.com/v1/orders" })
      ).rejects.toThrow("requires global fetch");
    } finally {
      globalThis.fetch = previous;
    }
  });
});

describe("protected-resource redirect to a plaintext origin", () => {
  it("refuses a plaintext redirect target that is not loopback", async () => {
    const session = {
      authenticationHeaders: () => Promise.resolve({ Authorization: "AEP a.b.c" }),
      inspect: () => Promise.resolve(inspectResult()),
      openApiPolicy: () =>
        Promise.resolve({
          freshness: "fetched",
          methods: ["aep-jwt"],
          source: "openapi",
          state: "required"
        })
    } as unknown as AepServiceSession;

    await expect(
      fetchProtectedResource({
        agent: { serviceSession: () => session },
        fetch: () =>
          Promise.resolve(
            new Response(null, {
              status: 302,
              headers: { location: "http://api.example.com/v1/orders" }
            })
          ) as never,
        url: "http://localhost:4100/v1/orders"
      })
    ).rejects.toThrow("plaintext origin");
  });
});

describe("response shapes", () => {
  it("treats a ResponseLike without ok as a failure", async () => {
    const result = await probeProtectedResource({
      fetch: () =>
        Promise.resolve({
          ok: false,
          status: 500,
          headers: { get: () => null }
        } as unknown as ResponseLike) as never,
      url: "https://api.example.com/v1/orders"
    });

    expect(result.classification).toBe("http-response");
  });
});

describe("stored credential expiry", () => {
  const SERVICE = "did:web:api.example.com";

  function record(
    credentialId: string,
    overrides: Partial<AepSessionCredentialRecord> = {}
  ): AepSessionCredentialRecord {
    return {
      credential: {
        access_token: "token",
        credential_id: credentialId,
        expires_at: "2999-01-01T00:00:00Z",
        scopes: [],
        token_type: "Bearer"
      },
      credentialId,
      expiresAt: "2999-01-01T00:00:00Z",
      grantType: "oauth-bearer",
      issuedAt: "2026-01-01T00:00:00Z",
      serviceDid: SERVICE,
      ...overrides
    };
  }

  it("presents a credential that is still within its record expiry", () => {
    const store = createInMemorySessionCredentialStore([record("cred-live")]);

    expect(store.findUsableCredential(SERVICE, new Date("2026-05-28T12:00:00Z"))).toMatchObject({
      credentialId: "cred-live"
    });
  });

  it("falls back to the credential's own expires_at when the record omits one", () => {
    const { expiresAt: _recordExpiry, ...withoutRecordExpiry } = record("cred-body-expiry");
    const store = createInMemorySessionCredentialStore([withoutRecordExpiry]);

    expect(store.findUsableCredential(SERVICE, new Date("2026-05-28T12:00:00Z"))).toMatchObject({
      credentialId: "cred-body-expiry"
    });
  });

  it("discards a record whose expiry has passed", () => {
    const store = createInMemorySessionCredentialStore([
      record("cred-expired", {
        credential: {
          access_token: "token",
          credential_id: "cred-expired",
          expires_at: "2026-01-02T00:00:00Z",
          scopes: [],
          token_type: "Bearer"
        },
        expiresAt: "2026-01-02T00:00:00Z"
      })
    ]);

    expect(store.findUsableCredential(SERVICE, new Date("2026-05-28T12:00:00Z"))).toBeUndefined();
  });

  it("discards a record with no determinable expiry rather than presenting it", () => {
    const { expiresAt: _noExpiry, ...withoutAnyExpiry } = record("cred-no-expiry", {
      credential: {
        access_token: "token",
        credential_id: "cred-no-expiry",
        scopes: [],
        token_type: "Bearer"
      } as never
    });
    const store = createInMemorySessionCredentialStore([withoutAnyExpiry]);

    expect(store.findUsableCredential(SERVICE, new Date("2026-05-28T12:00:00Z"))).toBeUndefined();
  });

  it("discards a record whose expiry is not a parseable instant", () => {
    const store = createInMemorySessionCredentialStore([
      record("cred-bad-expiry", { expiresAt: "not-a-date" })
    ]);

    expect(store.findUsableCredential(SERVICE, new Date("2026-05-28T12:00:00Z"))).toBeUndefined();
  });

  it("ignores credentials issued for another Service", () => {
    const store = createInMemorySessionCredentialStore([
      record("cred-other", { serviceDid: "did:web:other.example" })
    ]);

    expect(store.findUsableCredential(SERVICE, new Date("2026-05-28T12:00:00Z"))).toBeUndefined();
  });
});
