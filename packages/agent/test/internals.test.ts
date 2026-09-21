import { AEP_MEDIA_TYPE } from "@aep-foundation/core";
import type { PlatformAgentIdentity } from "@aep-foundation/core";
import { describe, expect, it } from "vitest";

import {
  buildClientAssertionClaims,
  createInMemoryPublicDocumentCache,
  createPlatformDelegatedSigner,
  createPlatformIdentityProvider,
  discoverPlatform,
  enrollService,
  fetchAepPublicDocument,
  inspectService,
  interpretAepOpenApiOperation,
  listPlatformIdentities,
  provisionPlatformIdentity,
  selectGrantType,
  sessionCredentialRecordFromGrantResult,
  statusService
} from "../src/index.js";
import type { GrantServiceResult, InspectServiceResult } from "../src/index.js";

const SERVICE_DID = "did:web:api.example.com";
const AGENT_DID = "did:web:agent.example.com:agents:123";
const PLATFORM_URL = "https://platform.example.com";

const inspectDocumentFixture = {
  aep_version: "1.0",
  bindings: { supported: ["http"] },
  commands: { supported: ["enroll", "inspect", "status"] },
  core: { signing_algorithms: ["EdDSA", "ES256"] },
  http: { endpoint_base: "/aep/" },
  identity: { methods: ["did:web"] },
  service: { did: SERVICE_DID }
};

const discoveryDocument = {
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
    did_url_template: "https://platform.example.com/agents/{agent_did_id}/did.json"
  },
  platform: { did: "did:web:platform.example.com", hosted_verification: true, name: "Example" },
  signing: { algorithms: ["ES256"], default_lifetime_seconds: "300" }
};

function platformIdentity(overrides: Partial<PlatformAgentIdentity> = {}): Record<string, unknown> {
  return {
    agent_did: "did:web:platform.example.com:a:opaque",
    agent_identity_id: "pai_1",
    created_at: "2026-07-06T12:00:00Z",
    did_document_url: "https://platform.example.com/a/opaque/did.json",
    key_id: "did:web:platform.example.com:a:opaque",
    service_did: SERVICE_DID,
    signing_algorithms: ["ES256"],
    status: "active",
    updated_at: "2026-07-06T12:00:00Z",
    ...overrides
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

function discoveryOr(
  document: unknown,
  handler: (input: URL | string, init?: RequestInit) => Promise<unknown> = () =>
    Promise.reject(new Error("unexpected request"))
): (input: URL | string, init?: RequestInit) => Promise<unknown> {
  return (input, init) =>
    String(input).includes("/.well-known/aep-platform")
      ? Promise.resolve(json(document))
      : handler(input, init);
}

describe("Platform discovery document validation", () => {
  async function discoverWith(overrides: Record<string, unknown>): Promise<Error> {
    try {
      await withFetch(discoveryOr({ ...discoveryDocument, ...overrides }), () =>
        discoverPlatform({ platformUrl: PLATFORM_URL })
      );
      throw new Error("expected a rejection");
    } catch (error) {
      return error as Error;
    }
  }

  it("requires the platform DID to be a DID", async () => {
    const error = await discoverWith({
      platform: { ...discoveryDocument.platform, did: "platform.example.com" }
    });
    expect(error.message).toContain("did must be a DID");
  });

  it("requires the DID URL template to use HTTPS", async () => {
    const error = await discoverWith({
      identity: {
        ...discoveryDocument.identity,
        did_url_template: "http://platform.example.com/a/{agent_did_id}/did.json"
      }
    });
    expect(error.message).toContain("did_url_template must use HTTPS");
  });

  it("requires usable signing algorithms", async () => {
    const error = await discoverWith({
      signing: { ...discoveryDocument.signing, algorithms: [] }
    });
    expect(error.message).toContain("signing algorithms are invalid");
  });

  it("requires a platform name", async () => {
    const error = await discoverWith({
      platform: { ...discoveryDocument.platform, name: "" }
    });
    expect(error.message).toContain("name must be a non-empty string");
  });

  it("requires the endpoints object to be an object", async () => {
    const error = await discoverWith({ endpoints: "not-an-object" });
    expect(error.message).toContain("must be an object");
  });

  it("requires hosted_verification to be a boolean", async () => {
    const error = await discoverWith({
      platform: { ...discoveryDocument.platform, hosted_verification: "true" }
    });
    expect(error.message).toContain("must be a boolean");
  });

  it("requires did_methods to be a string array", async () => {
    const error = await discoverWith({
      identity: { ...discoveryDocument.identity, did_methods: "did:web" }
    });
    expect(error.message).toContain("must be a string array");
  });

  it("reports an endpoint the Platform does not advertise", async () => {
    const { lifecycle: _lifecycle, ...endpoints } = discoveryDocument.endpoints;
    const discovery = await withFetch(
      discoveryOr({ ...discoveryDocument, endpoints: { ...endpoints, lifecycle: undefined } }),
      () => discoverPlatform({ platformUrl: PLATFORM_URL })
    ).catch((error: unknown) => error as Error);

    expect(discovery).toBeInstanceOf(Error);
  });

  it("normalizes a Platform URL down to its origin", async () => {
    let discoveryUrl = "";
    await withFetch(
      (input) => {
        discoveryUrl = String(input);
        return Promise.resolve(json(discoveryDocument));
      },
      () => discoverPlatform({ platformUrl: "https://platform.example.com/deep/path?q=1#frag" })
    );

    expect(discoveryUrl).toBe("https://platform.example.com/.well-known/aep-platform");
  });
});

describe("Platform response validation", () => {
  it("requires the identity list data to be an array", async () => {
    await expect(
      withFetch(
        discoveryOr(discoveryDocument, () =>
          Promise.resolve(json({ count: "0", data: "none", total: "0" }))
        ),
        () => listPlatformIdentities({ platformUrl: PLATFORM_URL })
      )
    ).rejects.toThrow("list data must be an array");
  });

  it("requires a supported managed Agent status", async () => {
    await expect(
      withFetch(
        discoveryOr(discoveryDocument, () =>
          Promise.resolve(json(platformIdentity({ status: "archived" as never })))
        ),
        () =>
          provisionPlatformIdentity({
            idempotencyKey: "key-1",
            platformUrl: PLATFORM_URL,
            serviceDid: SERVICE_DID
          })
      )
    ).rejects.toThrow("supported managed Agent status");
  });

  it("requires a non-empty string field", async () => {
    await expect(
      withFetch(
        discoveryOr(discoveryDocument, () =>
          Promise.resolve(json(platformIdentity({ agent_identity_id: "" })))
        ),
        () =>
          provisionPlatformIdentity({
            idempotencyKey: "key-1",
            platformUrl: PLATFORM_URL,
            serviceDid: SERVICE_DID
          })
      )
    ).rejects.toThrow("must be a non-empty string");
  });
});

describe("Platform delegated signing responses", () => {
  function signWith(body: unknown): Promise<unknown> {
    return withFetch(
      discoveryOr(discoveryDocument, () => Promise.resolve(json(body))),
      () => {
        const signer = createPlatformDelegatedSigner({
          identity: platformIdentity() as unknown as PlatformAgentIdentity,
          platformUrl: PLATFORM_URL
        });
        const claims = buildClientAssertionClaims({
          agentDid: "did:web:platform.example.com:a:opaque",
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
  }

  it("returns a pending result with its retry cadence", async () => {
    await expect(signWith({ retry_after_seconds: "5", status: "pending" })).resolves.toMatchObject({
      retryAfterSeconds: 5,
      status: "pending"
    });
  });

  it("bounds the retry cadence to 1 through 300 seconds", async () => {
    for (const retry_after_seconds of ["0", "301", "abc"]) {
      await expect(signWith({ retry_after_seconds, status: "pending" })).rejects.toThrow(
        "retry_after_seconds must be from 1 through 300"
      );
    }
  });

  it("rejects a status that is neither completed nor pending", async () => {
    await expect(signWith({ status: "failed" })).rejects.toThrow(
      "status must be completed or pending"
    );
  });
});

describe("Platform-hosted identity metadata", () => {
  it("reports metadata a hosted identity is missing", async () => {
    const provider = createPlatformIdentityProvider({ platformUrl: PLATFORM_URL });

    await expect(
      withFetch(discoveryOr(discoveryDocument), async () =>
        provider.signerFor({
          agentDid: "did:web:platform.example.com:a:opaque",
          identityKind: "platform-hosted",
          serviceDid: SERVICE_DID,
          signingAlgorithms: ["ES256"]
        })
      )
    ).rejects.toThrow("metadata is missing");
  });

  it("builds a signer from complete hosted metadata", async () => {
    const provider = createPlatformIdentityProvider({ platformUrl: PLATFORM_URL });

    const signer = await withFetch(discoveryOr(discoveryDocument), async () =>
      provider.signerFor({
        agentDid: "did:web:platform.example.com:a:opaque",
        identityKind: "platform-hosted",
        metadata: {
          agentIdentityId: "pai_1",
          createdAt: "2026-07-06T12:00:00Z",
          didDocumentUrl: "https://platform.example.com/a/opaque/did.json",
          keyId: "did:web:platform.example.com:a:opaque",
          status: "active",
          updatedAt: "2026-07-06T12:00:00Z"
        },
        serviceDid: SERVICE_DID,
        signingAlgorithms: ["ES256"]
      })
    );

    expect(typeof signer).toBe("function");
  });
});

describe("command credential resolution", () => {
  const inspect = {
    document: inspectDocumentFixture,
    inspectUrl: new URL("https://api.example.com/.well-known/aep"),
    commandUrl: (command: string) => new URL(`/aep/${command}`, "https://api.example.com")
  } as unknown as InspectServiceResult;

  it("requires a client assertion or a signer", async () => {
    await expect(statusService({ inspect, serviceUrl: "https://api.example.com" })).rejects.toThrow(
      "requires clientAssertion or clientAssertionSigner"
    );
  });

  it("requires an Agent DID when signing", async () => {
    await expect(
      statusService({
        clientAssertionSigner: () => Promise.resolve("a.b.c"),
        inspect,
        serviceUrl: "https://api.example.com"
      })
    ).rejects.toThrow("requires agentDid");
  });

  it("surfaces an abort before signing begins", async () => {
    const controller = new AbortController();
    controller.abort(new Error("cancelled by caller"));

    await expect(
      enrollService({
        agentDid: AGENT_DID,
        clientAssertionSigner: () => Promise.resolve("a.b.c"),
        idempotencyKey: "key-1",
        inspect,
        serviceUrl: "https://api.example.com",
        signal: controller.signal
      })
    ).rejects.toThrow("cancelled by caller");
  });
});

describe("Grant result helpers", () => {
  it("selects from a bare Inspect document and rejects a document without grants", () => {
    expect(
      selectGrantType({
        ...inspectDocumentFixture,
        commands: { ...inspectDocumentFixture.commands, grant_types: ["api-key"] }
      })
    ).toBe("api-key");
    expect(() => selectGrantType(inspectDocumentFixture)).toThrow("compatible grant type");
  });

  function grantResult(body: unknown): GrantServiceResult {
    return {
      body,
      commandUrl: new URL("https://api.example.com/aep/grant"),
      status: 200
    } as GrantServiceResult;
  }

  it("keeps an extension credential without inventing an expiry or Service URL", () => {
    const record = sessionCredentialRecordFromGrantResult(
      grantResult({ credential_id: "extension-1", token: "opaque" }),
      {
        grantType: "custom-token",
        inspect: inspectDocumentFixture
      }
    );
    expect(record).toMatchObject({
      credentialId: "extension-1",
      grantType: "custom-token",
      serviceDid: SERVICE_DID
    });
    expect(record).not.toHaveProperty("expiresAt");
    expect(record).not.toHaveProperty("serviceUrl");
  });

  it("requires a credential identifier in the Grant response", () => {
    expect(() =>
      sessionCredentialRecordFromGrantResult(grantResult({ access_token: "token" }), {
        grantType: "oauth-bearer",
        inspect: inspectDocumentFixture
      })
    ).toThrow("does not include credential_id");
  });

  it("records a credential from a complete Grant response", () => {
    const record = sessionCredentialRecordFromGrantResult(
      grantResult({
        access_token: "token",
        credential_id: "cred-1",
        expires_at: "2999-01-01T00:00:00Z",
        token_type: "Bearer"
      }),
      {
        grantType: "oauth-bearer",
        inspect: inspectDocumentFixture,
        serviceUrl: "https://api.example.com"
      }
    );

    expect(record).toMatchObject({
      credentialId: "cred-1",
      expiresAt: "2999-01-01T00:00:00Z",
      grantType: "oauth-bearer",
      serviceDid: SERVICE_DID,
      serviceUrl: "https://api.example.com"
    });
  });
});

describe("Inspect transport bounds", () => {
  const options = { serviceUrl: "https://api.example.com" };

  it.each([false, true])("reads bounded custom responses with a text reader=%s", async (text) => {
    const fetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: () => Promise.resolve({ value: "ok" }),
        ...(text ? { text: () => Promise.resolve('{"value":"ok"}') } : {})
      });
    const request = {
      accept: "application/json",
      namespace: "openapi" as const,
      url: "https://api.example.com/openapi.json",
      fetch,
      parse: (value: unknown) => value
    };
    await expect(
      fetchAepPublicDocument({ ...request, maxResponseBytes: 64 })
    ).resolves.toMatchObject({ value: { value: "ok" } });
    await expect(fetchAepPublicDocument({ ...request, maxResponseBytes: 1 })).rejects.toThrow(
      "too large"
    );
  });

  it("requires a positive timeout", async () => {
    await expect(inspectService({ ...options, timeoutMs: 0 })).rejects.toThrow(
      /timeoutMs must be a positive integer/
    );
  });

  it("requires a positive response bound", async () => {
    await expect(
      withFetch(
        () =>
          Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ "content-type": AEP_MEDIA_TYPE }),
            body: new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array(4));
                controller.close();
              }
            }),
            json: () => Promise.resolve(inspectDocumentFixture)
          }),
        () => inspectService({ ...options, maxResponseBytes: 0 })
      )
    ).rejects.toThrow();
  });

  it("reads a streamed Inspect response within the bound", async () => {
    const payload = new TextEncoder().encode(JSON.stringify(inspectDocumentFixture));
    const result = await withFetch(
      () =>
        Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ "content-type": AEP_MEDIA_TYPE }),
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(payload.slice(0, 10));
              controller.enqueue(payload.slice(10));
              controller.close();
            }
          }),
          json: () => Promise.resolve(inspectDocumentFixture)
        }),
      () => inspectService(options)
    );

    expect(result.document.service.did).toBe(SERVICE_DID);
  });

  it("reports a streamed Inspect response that exceeds the bound", async () => {
    await expect(
      withFetch(
        () =>
          Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ "content-type": AEP_MEDIA_TYPE }),
            body: new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array(64));
                controller.close();
              }
            }),
            json: () => Promise.resolve(inspectDocumentFixture)
          }),
        () => inspectService({ ...options, maxResponseBytes: 8 })
      )
    ).rejects.toThrow();
  });
});

describe("public document cache behavior", () => {
  const document = { aep_version: "1.0" };
  const parse = (value: unknown): { aep_version: string } => value as { aep_version: string };

  it("seeds from records", async () => {
    const cache = createInMemoryPublicDocumentCache([
      {
        namespace: "inspect",
        url: "https://api.example.com/.well-known/aep",
        value: document,
        cachedAt: new Date().toISOString(),
        cacheControl: "max-age=300"
      }
    ]);

    const result = await fetchAepPublicDocument({
      accept: AEP_MEDIA_TYPE,
      cache,
      namespace: "inspect",
      parse,
      url: "https://api.example.com/.well-known/aep"
    });

    expect(result.freshness).toBe("fresh");
  });

  it("does not persist a no-store representation", async () => {
    const cache = createInMemoryPublicDocumentCache();

    await fetchAepPublicDocument({
      accept: AEP_MEDIA_TYPE,
      cache,
      fetch: () =>
        Promise.resolve(json(document, { "cache-control": "no-store" }) as unknown as never),
      namespace: "inspect",
      parse,
      url: "https://api.example.com/.well-known/aep"
    });

    expect(await cache.get("inspect", "https://api.example.com/.well-known/aep")).toBeUndefined();
  });

  it("refetches rather than reusing a no-cache representation", async () => {
    const cache = createInMemoryPublicDocumentCache([
      {
        namespace: "inspect",
        url: "https://api.example.com/.well-known/aep",
        value: document,
        cachedAt: new Date().toISOString(),
        cacheControl: "no-cache"
      }
    ]);
    let calls = 0;

    await fetchAepPublicDocument({
      accept: AEP_MEDIA_TYPE,
      cache,
      fetch: () => {
        calls += 1;
        return Promise.resolve(json(document) as unknown as never);
      },
      namespace: "inspect",
      parse,
      url: "https://api.example.com/.well-known/aep"
    });

    expect(calls).toBe(1);
  });

  it("discards a cached final URL that names another origin", async () => {
    const cache = createInMemoryPublicDocumentCache([
      {
        namespace: "inspect",
        url: "https://api.example.com/.well-known/aep",
        finalUrl: "https://attacker.example/.well-known/aep",
        value: document,
        cachedAt: "2000-01-01T00:00:00Z"
      }
    ]);
    const requested: string[] = [];

    await fetchAepPublicDocument({
      accept: AEP_MEDIA_TYPE,
      cache,
      fetch: (input) => {
        requested.push(String(input));
        return Promise.resolve(json(document) as unknown as never);
      },
      namespace: "inspect",
      parse,
      sameOriginRedirects: true,
      url: "https://api.example.com/.well-known/aep"
    });

    expect(requested).toEqual(["https://api.example.com/.well-known/aep"]);
  });

  it("reports a malformed JSON payload", async () => {
    await expect(
      fetchAepPublicDocument({
        accept: AEP_MEDIA_TYPE,
        fetch: () =>
          Promise.resolve(
            new Response("{not json", {
              headers: { "content-type": AEP_MEDIA_TYPE }
            }) as unknown as never
          ),
        namespace: "inspect",
        parse,
        url: "https://api.example.com/.well-known/aep"
      })
    ).rejects.toThrow("malformed JSON");
  });

  it("requires a positive response bound and enforces it", async () => {
    await expect(
      fetchAepPublicDocument({
        accept: AEP_MEDIA_TYPE,
        fetch: () => Promise.resolve(json(document) as unknown as never),
        maxResponseBytes: 0,
        namespace: "inspect",
        parse,
        url: "https://api.example.com/.well-known/aep"
      })
    ).rejects.toThrow("must be a positive integer");

    await expect(
      fetchAepPublicDocument({
        accept: AEP_MEDIA_TYPE,
        fetch: () => Promise.resolve(json(document) as unknown as never),
        maxResponseBytes: 4,
        namespace: "inspect",
        parse,
        url: "https://api.example.com/.well-known/aep"
      })
    ).rejects.toThrow("too large");
  });

  it("rejects a response whose media type is not accepted", async () => {
    for (const contentType of [
      "text/plain",
      "not a media type",
      "application/aep+json; =bad",
      ""
    ]) {
      await expect(
        fetchAepPublicDocument({
          accept: AEP_MEDIA_TYPE,
          acceptedMediaTypes: [AEP_MEDIA_TYPE],
          fetch: () =>
            Promise.resolve(
              new Response(JSON.stringify(document), {
                headers: { "content-type": contentType }
              }) as unknown as never
            ),
          namespace: "inspect",
          parse,
          url: "https://api.example.com/.well-known/aep"
        })
      ).rejects.toThrow("media type is invalid");
    }
  });

  it("accepts a media type carrying the expected parameter", async () => {
    const result = await fetchAepPublicDocument({
      accept: "application/vnd.oai.openapi+json",
      acceptedMediaTypes: ["application/vnd.oai.openapi+json;version=3.1"],
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify(document), {
            headers: { "content-type": 'application/vnd.oai.openapi+json; version="3.1"' }
          }) as unknown as never
        ),
      namespace: "openapi",
      parse,
      url: "https://api.example.com/openapi.json"
    });

    expect(result.freshness).toBe("fetched");
  });
});

describe("OpenAPI operation interpretation", () => {
  const request = {
    method: "GET",
    trailingSlash: "strict" as const,
    url: "https://api.example.com/v1/orders"
  };

  it("requires an OpenAPI 3.1 document", () => {
    expect(() => interpretAepOpenApiOperation({ openapi: "3.0.3" }, request)).toThrow(
      "must use OpenAPI 3.1"
    );
    expect(() => interpretAepOpenApiOperation({}, request)).toThrow("must use OpenAPI 3.1");
  });

  it("falls back when the document defines no paths", () => {
    expect(interpretAepOpenApiOperation({ openapi: "3.1.0" }, request)).toMatchObject({
      state: "fallback"
    });
  });

  it.each([
    { path: "/", trailingSlash: "strict" as const, suggestion: "/" },
    { path: "/missing/", trailingSlash: "strict" as const, suggestion: "/missing" },
    { path: "/missing", trailingSlash: "equivalent" as const, suggestion: undefined }
  ])(
    "falls back on unmatched paths without treating them as public: $path",
    ({ path, trailingSlash, suggestion }) => {
      const result = interpretAepOpenApiOperation(
        { openapi: "3.1.0", paths: {} },
        {
          url: `https://api.example.com${path}`,
          trailingSlash
        }
      );
      expect(result.state).toBe("fallback");
      expect(result.strictSlashSuggestion).toBe(suggestion);
    }
  );

  it.each([undefined, { bearer: { type: "http", scheme: "bearer" } }])(
    "does not infer AEP authentication from an unmapped security scheme: %j",
    (securitySchemes) => {
      expect(
        interpretAepOpenApiOperation(
          {
            openapi: "3.1.0",
            components: { securitySchemes },
            paths: { "/v1/orders": { get: { security: [{ bearer: [] }] } } }
          },
          request
        )
      ).toMatchObject({ state: "fallback", methods: [] });
    }
  );

  it("falls back when two templates are equally specific", () => {
    const document = {
      openapi: "3.1.0",
      paths: {
        "/v1/{kind}": { get: {} },
        "/v1/{group}": { get: {} }
      }
    };

    expect(
      interpretAepOpenApiOperation(document, {
        ...request,
        url: "https://api.example.com/v1/orders"
      })
    ).toMatchObject({ state: "fallback" });
  });

  it("ignores a requirement entry that is not an object", () => {
    const document = {
      openapi: "3.1.0",
      components: {
        securitySchemes: { aep: { type: "http", "x-aep-authentication-method": "aep-jwt" } }
      },
      paths: { "/v1/orders": { get: { security: ["not-an-object", { aep: [] }] } } }
    };

    expect(interpretAepOpenApiOperation(document, request)).toMatchObject({
      methods: ["aep-jwt"],
      state: "required"
    });
  });

  it("treats an empty requirement object as permitting anonymous access", () => {
    const document = {
      openapi: "3.1.0",
      paths: { "/v1/orders": { get: { security: [{}] } } }
    };

    expect(interpretAepOpenApiOperation(document, request)).toMatchObject({ state: "public" });
  });

  it("prefers a literal segment over a templated one", () => {
    const document = {
      openapi: "3.1.0",
      components: {
        securitySchemes: { aep: { type: "http", "x-aep-authentication-method": "aep-jwt" } }
      },
      paths: {
        "/v1/{kind}": { get: { security: [] } },
        "/v1/orders": { get: { security: [{ aep: [] }] } }
      }
    };

    expect(interpretAepOpenApiOperation(document, request)).toMatchObject({
      matchedOperation: { method: "GET", pathTemplate: "/v1/orders" },
      state: "required"
    });
  });
});
