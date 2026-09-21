import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";

import { AEP_MEDIA_TYPE, verifyClientAssertionJwt } from "@aep-foundation/core";
import type { InspectDocument, PlatformAgentIdentity } from "@aep-foundation/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AepPendingSignError,
  createAepAgent,
  createInMemoryAgentIdentityStore,
  createInMemoryPublicDocumentCache,
  createInMemorySessionCredentialStore,
  createJwtClientAssertionSigner,
  createPlatformDelegatedSigner,
  createPlatformIdentityProvider,
  discoverPlatform,
  fetchProtectedResource,
  listPlatformIdentities,
  probeProtectedResource,
  provisionPlatformIdentity
} from "../src/index.js";
import type { AepAgentOptions, AepSessionCredentialRecord } from "../src/index.js";

const document: InspectDocument = {
  aep_version: "1.0",
  authentication: { methods: ["api-key", "oauth-bearer"] },
  bindings: { supported: ["http"] },
  commands: {
    supported: ["inspect", "enroll", "status", "grant", "revoke"],
    grant_types: ["api-key", "oauth-bearer"]
  },
  core: { signing_algorithms: ["EdDSA", "ES256"] },
  http: { endpoint_base: "/aep/" },
  identity: { methods: ["did:web"] },
  service: { did: "did:web:api.example.com" }
};
const identity = {
  agentDid: "did:web:agent.example",
  serviceDid: document.service.did,
  identityKind: "sovereign" as const,
  signingAlgorithms: ["EdDSA" as const]
};
const { privateKey } = generateKeyPairSync("ed25519");
const signer = createJwtClientAssertionSigner({ alg: "EdDSA", key: privateKey });
const expires = "2099-01-01T00:00:00Z";
const apiCredential = {
  credential_id: "api",
  api_key: "test-api-secret",
  header: "X-Service-Key",
  expires_at: expires
};
const records: AepSessionCredentialRecord[] = [
  { credentialId: "api", grantType: "api-key", credential: apiCredential },
  {
    credentialId: "bearer",
    grantType: "oauth-bearer",
    credential: {
      credential_id: "bearer",
      access_token: "test-bearer-secret",
      token_type: "Bearer",
      expires_at: expires
    }
  }
].map((record) => ({
  ...record,
  serviceDid: identity.serviceDid,
  issuedAt: "2026-01-01T00:00:00Z",
  expiresAt: expires
}));

function requestJson(body: RequestInit["body"]): unknown {
  if (typeof body !== "string") throw new Error("Expected a JSON request body");
  return JSON.parse(body);
}

function json(value: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return Promise.resolve(
    Response.json(value, { headers: { "content-type": AEP_MEDIA_TYPE, ...headers } })
  );
}

function agent(fetch: typeof globalThis.fetch, overrides: Partial<AepAgentOptions> = {}) {
  return createAepAgent({
    fetch,
    identityProvider: { getOrCreateIdentity: () => identity, signerFor: () => signer },
    identityStore: createInMemoryAgentIdentityStore([identity]),
    credentialStore: createInMemorySessionCredentialStore(records),
    ...overrides
  });
}

const openapi = {
  openapi: "3.1.0",
  components: {
    securitySchemes: {
      bearer: { type: "http", scheme: "bearer", "x-aep-authentication-method": "oauth-bearer" }
    }
  },
  paths: { "/orders": { get: { security: [{ bearer: [] }] } } }
};
const policyDocument = {
  ...document,
  http: {
    ...document.http,
    openapi: { url: "/openapi.json", path_matching: { trailing_slash: "strict" } }
  }
};

afterEach(() => vi.unstubAllGlobals());

describe("session authentication selection", () => {
  it.each([false, true])(
    "replays a POST using a dedicated credential header, already stored=%s",
    async (stored) => {
      let resourceCalls = 0;
      let grants = 0;
      const credential = records[1];
      if (credential === undefined) throw new Error("missing bearer fixture");
      const fetch: typeof globalThis.fetch = async (input, init) => {
        const path = new URL(input instanceof Request ? input.url : String(input)).pathname;
        if (path === "/.well-known/aep") return json(document);
        if (path === "/aep/status")
          return json({ status: "active", since: "2026-01-01T00:00:00Z" });
        if (path === "/aep/grant") {
          grants++;
          return json(credential.credential);
        }
        expect(path).toBe("/orders");
        resourceCalls++;
        expect(init?.method).toBe("POST");
        expect(init?.body).toBe('{"quantity":1}');
        const headers = new Headers(init?.headers);
        if (resourceCalls === 1) {
          expect(headers.has("authorization")).toBe(false);
          expect(headers.has("aep-authorization")).toBe(false);
          return new Response(null, {
            status: 401,
            headers: {
              "WWW-Authenticate":
                'AEP service_did="did:web:api.example.com", inspect="https://api.example.com/.well-known/aep"'
            }
          });
        }
        expect(headers.get("authorization")).toBe("Payment opaque-proof");
        expect(headers.get("aep-authorization")).toBe("Bearer test-bearer-secret");
        return new Response("success");
      };
      const response = await fetchProtectedResource({
        agent: agent(fetch, {
          credentialStore: createInMemorySessionCredentialStore(stored ? [credential] : [])
        }),
        fetch,
        url: "https://api.example.com/orders",
        method: "POST",
        body: '{"quantity":1}',
        headers: { Authorization: "Payment opaque-proof" },
        grantType: "oauth-bearer",
        carrier: "dedicated"
      });
      expect(await response.text()).toBe("success");
      expect(resourceCalls).toBe(2);
      expect(grants).toBe(stored ? 0 : 1);
    }
  );

  it("uses configured assertion claims and carrier when credentials are deliberately bypassed", async () => {
    const { publicKey, privateKey: key } = generateKeyPairSync("ed25519");
    const jwtSigner = createJwtClientAssertionSigner({ alg: "EdDSA", key });
    const sign = vi.fn(jwtSigner);
    const now = new Date("2026-01-01T00:00:00Z");
    const session = agent(
      async () =>
        json({
          ...document,
          authentication: { methods: ["api-key", "aep-jwt"] }
        }),
      {
        allowInsecureLoopback: false,
        assertionClock: () => now,
        assertionJti: () => "configured-jti",
        assertionTtlSeconds: 60,
        identityProvider: { getOrCreateIdentity: () => identity, signerFor: () => sign }
      }
    ).serviceSession({ serviceUrl: "https://api.example.com" });
    const headers = await session.authenticationHeaders({
      preferCredential: false,
      resource: "https://api.example.com/orders",
      carrier: "dedicated"
    });
    const token = headers["AEP-Authorization"]?.replace(/^AEP /u, "");
    if (token === undefined) throw new Error("missing dedicated assertion");
    await expect(
      verifyClientAssertionJwt(token, {
        key: publicKey,
        currentDate: now,
        audience: identity.serviceDid,
        issuer: identity.agentDid,
        allowInsecureLoopback: false
      })
    ).resolves.toMatchObject({ op: "authenticate", jti: "configured-jti" });
    expect(sign).toHaveBeenCalledWith(
      expect.objectContaining({
        op: "authenticate",
        resource: "https://api.example.com/orders",
        jti: "configured-jti",
        iat: now.getTime() / 1000,
        exp: now.getTime() / 1000 + 60
      }),
      expect.objectContaining({ command: "authenticate" })
    );
    expect(headers).not.toHaveProperty("X-Service-Key");
    await expect(session.authenticationHeaders({ preferCredential: false })).rejects.toThrow(
      "protected-resource URI"
    );
  });

  it.each(["timeout", "caller"])(
    "cancels a protected-resource request on %s abort",
    async (reason) => {
      const caller = new AbortController();
      const fetch: typeof globalThis.fetch = async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.endsWith("/.well-known/aep")) return json(document);
        const signal = init?.signal;
        if (signal === undefined || signal === null) throw new Error("missing request signal");
        return new Promise<Response>((_resolve, reject) => {
          const rejectAborted = () => {
            const reason: unknown = signal.reason;
            reject(reason instanceof Error ? reason : new Error("aborted"));
          };
          signal.addEventListener("abort", rejectAborted, { once: true });
          if (reason === "caller") caller.abort(new Error("caller cancelled"));
          if (signal.aborted) rejectAborted();
        });
      };
      await expect(
        fetchProtectedResource({
          agent: agent(fetch),
          fetch,
          signal: caller.signal,
          timeoutMs: reason === "timeout" ? 10 : 10_000,
          url: "https://api.example.com/orders"
        })
      ).rejects.toThrow(reason === "caller" ? "caller cancelled" : "aborted");
    }
  );

  it("keeps a POST probe anonymous and forwards its replayable body without mutating headers", async () => {
    const headers = {
      Authorization: "Bearer caller",
      "AEP-Authorization": "AEP caller",
      "Payment-Signature": "payment",
      "Content-Type": "application/json"
    };
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/.well-known/aep")) return json(document);
      expect(init?.method).toBe("POST");
      expect(init?.body).toBe('{"query":"plants"}');
      expect(Object.fromEntries(new Headers(init?.headers))).toEqual({
        "content-type": "application/json"
      });
      return new Response("public result");
    };
    const response = await fetchProtectedResource({
      agent: agent(fetch),
      fetch,
      headers,
      method: "POST",
      body: '{"query":"plants"}',
      url: "https://api.example.com/search"
    });
    expect(await response.text()).toBe("public result");
    expect(headers.Authorization).toBe("Bearer caller");
    expect(headers["AEP-Authorization"]).toBe("AEP caller");
    expect(headers["Payment-Signature"]).toBe("payment");
  });

  it("rejects conflicting explicit selections and preserves preference when none is supplied", async () => {
    const session = agent(async () => json(document)).serviceSession({
      serviceUrl: "https://api.example.com"
    });
    await expect(
      session.authenticationHeaders({ credentialId: "api", grantType: "oauth-bearer" })
    ).rejects.toThrow("does not match");
    await expect(session.authenticationHeaders()).resolves.toEqual({
      "X-Service-Key": "test-api-secret"
    });
  });

  it.each([undefined, "api", "missing"])(
    "honors operation policy with credential selection %s",
    async (credentialId) => {
      const sent: Headers[] = [];
      const fetch: typeof globalThis.fetch = async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.endsWith("/.well-known/aep")) return json(policyDocument);
        if (url.endsWith("/openapi.json")) return Response.json(openapi);
        sent.push(new Headers(init?.headers));
        return new Response("ok");
      };
      const result = fetchProtectedResource({
        agent: agent(fetch),
        fetch,
        url: "https://api.example.com/orders",
        ...(credentialId === undefined ? {} : { credentialId })
      });
      if (credentialId === undefined) {
        expect((await result).status).toBe(200);
        expect(sent).toHaveLength(1);
        expect(sent[0]?.get("authorization")).toBe("Bearer test-bearer-secret");
        expect(sent[0]?.has("x-service-key")).toBe(false);
      } else {
        await expect(result).rejects.toThrow();
        expect(sent).toHaveLength(0);
      }
    }
  );

  it("requires a new destination challenge even when OpenAPI requires authentication", async () => {
    const sent: { origin: string; headers: Headers }[] = [];
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.pathname === "/.well-known/aep")
        return json({ ...policyDocument, service: { did: `did:web:${url.hostname}` } });
      if (url.pathname === "/openapi.json") return Response.json(openapi);
      const headers = new Headers(init?.headers);
      sent.push({ origin: url.origin, headers });
      if (url.hostname === "api.example.com")
        return new Response(null, {
          status: 307,
          headers: { location: "https://other.example/orders" }
        });
      if (!headers.has("authorization"))
        return new Response(null, {
          status: 401,
          headers: {
            "www-authenticate":
              'AEP service_did = "did:web:other.example", inspect = "https://other.example/.well-known/aep"'
          }
        });
      return new Response("ok");
    };
    const client = agent(fetch, {
      credentialStore: createInMemorySessionCredentialStore([
        ...records,
        ...records.map((record) => ({ ...record, serviceDid: "did:web:other.example" }))
      ])
    });
    const response = await fetchProtectedResource({
      agent: client,
      fetch,
      url: "https://api.example.com/orders",
      headers: { "X-Caller-Key": "source-secret" }
    });
    expect(response.status).toBe(200);
    expect(sent).toHaveLength(3);
    expect(sent[1]?.origin).toBe("https://other.example");
    expect([...(sent[1]?.headers ?? [])]).toEqual([]);
    expect(sent[2]?.headers.get("authorization")).toBe("Bearer test-bearer-secret");
    expect(sent[2]?.headers.has("x-caller-key")).toBe(false);
  });

  it("keeps probes anonymous when a redirect returns to the original origin", async () => {
    const sent: Headers[] = [];
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.pathname === "/.well-known/aep")
        return json({ ...policyDocument, service: { did: `did:web:${url.hostname}` } });
      if (url.pathname === "/openapi.json") return Response.json(openapi);
      sent.push(new Headers(init?.headers));
      if (sent.length === 1)
        return new Response(null, {
          status: 307,
          headers: { location: "https://other.example/orders" }
        });
      if (sent.length === 2)
        return new Response(null, {
          status: 307,
          headers: { location: "https://api.example.com/orders" }
        });
      return new Response("public response");
    };
    const response = await fetchProtectedResource({
      agent: agent(fetch),
      fetch,
      url: "https://api.example.com/orders",
      headers: { "X-Caller-Key": "source-secret" }
    });
    expect(await response.text()).toBe("public response");
    expect(sent).toHaveLength(3);
    expect([...(sent[1] ?? [])]).toEqual([]);
    expect([...(sent[2] ?? [])]).toEqual([]);
  });

  it("rejects an explicit grant type excluded by the operation before creating a credential", async () => {
    const requests: string[] = [];
    const fetch: typeof globalThis.fetch = async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      requests.push(url);
      return url.endsWith("/.well-known/aep") ? json(policyDocument) : Response.json(openapi);
    };
    await expect(
      fetchProtectedResource({
        agent: agent(fetch),
        fetch,
        url: "https://api.example.com/orders",
        grantType: "api-key"
      })
    ).rejects.toThrow("not permitted");
    expect(
      requests.every((url) => url.endsWith("/.well-known/aep") || url.endsWith("/openapi.json"))
    ).toBe(true);
  });
});

describe("challenge whitespace", () => {
  it.each(["=", " = ", "\t=\t"])("accepts %j around equals", async (equals) => {
    const result = await probeProtectedResource({
      url: "https://api.example.com/orders",
      fetch: () =>
        Promise.resolve(
          new Response(null, {
            status: 401,
            headers: {
              "www-authenticate": `AEP service_did${equals}"${identity.serviceDid}", inspect${equals}"https://api.example.com/.well-known/aep"`
            }
          })
        )
    });
    expect(result.classification).toBe("aep-challenge");
  });
  it("still rejects duplicate parameters with whitespace", async () => {
    const result = await probeProtectedResource({
      url: "https://api.example.com/orders",
      fetch: () =>
        Promise.resolve(
          new Response(null, {
            status: 401,
            headers: {
              "www-authenticate": `AEP service_did = "${identity.serviceDid}", service_did="${identity.serviceDid}", inspect="https://api.example.com/.well-known/aep"`
            }
          })
        )
    });
    expect(result.classification).toBe("unrelated-authentication");
  });
});

describe("Grant request ownership and persistence", () => {
  it("forwards scopes to signing and granting and preserves targeted revocation parameters", async () => {
    const contexts = vi.fn(() => ({ purpose: "orders" }));
    const key = vi.fn(() => "command-key");
    const requests: Array<{ path: string; body: unknown }> = [];
    const sign = vi.fn(signer);
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const path = new URL(input instanceof Request ? input.url : String(input)).pathname;
      if (path === "/.well-known/aep")
        return json({
          ...document,
          commands: {
            ...document.commands,
            grant_types_config: { "api-key": { supports_per_credential_revoke: "true" } }
          }
        });
      if (path === "/aep/status") return json({ status: "active", since: "2026-01-01T00:00:00Z" });
      requests.push({ path, body: requestJson(init?.body) });
      return json(path === "/aep/grant" ? apiCredential : {});
    };
    const store = createInMemorySessionCredentialStore();
    const session = agent(fetch, {
      allowInsecureLoopback: false,
      assertionTtlSeconds: 60,
      credentialStore: store,
      platformContextProvider: contexts,
      idempotencyKeys: { createKey: key },
      identityProvider: { getOrCreateIdentity: () => identity, signerFor: () => sign }
    }).serviceSession({ serviceUrl: "https://api.example.com" });
    const scopes = ["read:orders"];
    await session.grant({ preferredGrantTypes: ["api-key"], requestedScopes: scopes });
    expect(contexts).toHaveBeenCalledWith(
      expect.objectContaining({ requestedScopes: scopes, grantType: "api-key" })
    );
    expect(sign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ command: "grant", platformContext: { purpose: "orders" } })
    );
    await session.revoke({
      grantType: "api-key",
      credentialId: "api",
      parameters: { reason: "finished" }
    });
    expect(key).toHaveBeenLastCalledWith(
      expect.objectContaining({ command: "revoke", credentialId: "api", grantType: "api-key" })
    );
    expect(requests).toEqual([
      { path: "/aep/grant", body: { grant_type: "api-key", requested_scopes: scopes } },
      {
        path: "/aep/revoke",
        body: { grant_type: "api-key", credential_id: "api", reason: "finished" }
      }
    ]);
    expect(await store.listCredentials(identity.serviceDid)).toEqual([]);
    expect(scopes).toEqual(["read:orders"]);
  });

  it.each(["parameters", "idempotency", "signal"])(
    "does not combine independent %s",
    async (difference) => {
      const requests: RequestInit[] = [];
      const fetch: typeof globalThis.fetch = async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.endsWith("/.well-known/aep")) return json(document);
        if (url.endsWith("/status"))
          return json({ status: "active", since: "2026-01-01T00:00:00Z" });
        requests.push(init ?? {});
        return json(apiCredential);
      };
      const session = agent(fetch).serviceSession({ serviceUrl: "https://api.example.com" });
      await Promise.all(
        ["first", "second"].map((value) =>
          session.grant({
            grantType: "api-key",
            ...(difference === "parameters" ? { parameters: { purpose: value } } : {}),
            ...(difference === "idempotency" ? { idempotencyKey: value } : {}),
            ...(difference === "signal" ? { signal: new AbortController().signal } : {})
          })
        )
      );
      expect(requests).toHaveLength(2);
      if (difference === "parameters")
        expect(requests.map((request) => request.body)).toEqual(
          expect.arrayContaining([
            JSON.stringify({ purpose: "first", grant_type: "api-key" }),
            JSON.stringify({ purpose: "second", grant_type: "api-key" })
          ])
        );
      if (difference === "idempotency")
        expect(
          requests.map((request) => new Headers(request.headers).get("idempotency-key")).sort()
        ).toEqual(["first", "second"]);
    }
  );

  it.each([false, true])(
    "shared callers wait for persistence, including failure=%s",
    async (fail) => {
      const backing = createInMemorySessionCredentialStore();
      let notifySaving = () => {};
      const saving = new Promise<void>((resolve) => {
        notifySaving = resolve;
      });
      let releaseSave = () => {};
      const release = new Promise<void>((resolve) => {
        releaseSave = resolve;
      });
      let grants = 0;
      const fetch: typeof globalThis.fetch = async (input) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.endsWith("/.well-known/aep")) return json(document);
        if (url.endsWith("/status"))
          return json({ status: "active", since: "2026-01-01T00:00:00Z" });
        grants++;
        return json(apiCredential);
      };
      const session = agent(fetch, {
        credentialStore: {
          ...backing,
          saveCredential: async (record) => {
            notifySaving();
            await release;
            if (fail) throw new Error("store failed");
            return backing.saveCredential(record);
          }
        }
      }).serviceSession({ serviceUrl: "https://api.example.com" });
      let settled = 0;
      const calls = [session.grant(), session.grant()];
      const results = Promise.allSettled(
        calls.map(async (call) => {
          try {
            return await call;
          } finally {
            settled++;
          }
        })
      );
      await saving;
      expect(grants).toBe(1);
      expect(settled).toBe(0);
      releaseSave();
      expect((await results).map((result) => result.status)).toEqual(
        fail ? ["rejected", "rejected"] : ["fulfilled", "fulfilled"]
      );
      expect(await backing.listCredentials(identity.serviceDid)).toHaveLength(fail ? 0 : 1);
      await session.grant().catch(() => undefined);
      expect(grants).toBe(2);
    }
  );
});

describe("pending signing across session commands", () => {
  it("preserves the cause of a failed resolver without sending an Enroll request", async () => {
    const failure = new Error("approval connection lost");
    const fetch = vi.fn(async () => json(document));
    const session = agent(fetch, {
      identityProvider: {
        getOrCreateIdentity: () => identity,
        signerFor: () => () => ({ status: "pending", retryAfterSeconds: 1 })
      },
      pendingSignResolver: () => {
        throw failure;
      }
    }).serviceSession({ serviceUrl: "https://api.example.com" });
    await expect(session.enroll()).rejects.toMatchObject({
      code: "resolver_failed",
      cause: failure
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("continues Enroll, Status, Grant's status check, and Revoke through the configured resolver", async () => {
    const resolved: string[] = [];
    const fetch: typeof globalThis.fetch = async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/.well-known/aep")) return json(document);
      if (url.endsWith("/grant")) return json(apiCredential);
      if (url.endsWith("/revoke")) return json({});
      return json({ status: "active", since: "2026-01-01T00:00:00Z" });
    };
    const client = agent(fetch, {
      identityProvider: {
        getOrCreateIdentity: () => identity,
        signerFor: () => async (claims, context) =>
          context.platformContext?.["approved"] === true
            ? signer(claims, context)
            : { status: "pending", retryAfterSeconds: 1, platformContext: { approved: true } }
      },
      pendingSignResolver: async (input) => {
        resolved.push(input.context.command);
        const result = await input.continueSign();
        if (result.status !== "completed") throw new Error("expected completion");
        return result;
      }
    });
    const session = client.serviceSession({ serviceUrl: "https://api.example.com" });
    await session.grant({ grantType: "api-key" });
    await session.enroll();
    await session.status();
    await session.revoke({ grantType: "api-key" });
    expect(resolved).toEqual(["status", "grant", "enroll", "status", "revoke"]);
  });

  it("retains the pending error without a resolver", async () => {
    const session = agent(async () => json(document), {
      identityProvider: {
        getOrCreateIdentity: () => identity,
        signerFor: () => () => ({ status: "pending", retryAfterSeconds: 1 })
      }
    }).serviceSession({ serviceUrl: "https://api.example.com" });
    await expect(session.enroll()).rejects.toBeInstanceOf(AepPendingSignError);
  });
});

const platformDocument = {
  aep_version: "1.0",
  platform: { name: "Platform", hosted_verification: false },
  http: { endpoint_base: "/aep" },
  identity: {
    did_methods: ["did:web"],
    did_url_template: "https://platform.example/agents/{id}/did.json"
  },
  signing: { algorithms: ["EdDSA"], default_lifetime_seconds: "300" },
  endpoints: {
    provision: "/provision",
    list: "/list",
    lifecycle: "/identities/{agent_identity_id}",
    sign: "/identities/{agent_identity_id}/sign"
  }
};
const platformIdentity: PlatformAgentIdentity = {
  agent_did: identity.agentDid,
  agent_identity_id: "123",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  did_document_url: "https://agent.example/did.json",
  key_id: "key",
  service_did: identity.serviceDid,
  signing_algorithms: ["EdDSA"],
  status: "active"
};
const claims = {
  iss: identity.agentDid,
  sub: identity.agentDid,
  aud: identity.serviceDid,
  op: "status" as const,
  jti: "test",
  iat: 1,
  exp: 301
};
const context = {
  command: "status" as const,
  serviceDid: identity.serviceDid,
  signingAlgorithms: ["EdDSA" as const]
};

describe("Grant identity recovery", () => {
  it.each(["active", "suspended", "missing"])(
    "recovers an existing Platform identity with Service enrollment %s without provisioning",
    async (status) => {
      const paths: string[] = [];
      const identityStore = createInMemoryAgentIdentityStore();
      const credentialStore = createInMemorySessionCredentialStore();
      const fetch: typeof globalThis.fetch = async (input) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        paths.push(url.pathname);
        switch (url.pathname) {
          case "/.well-known/aep":
            return json(document);
          case "/.well-known/aep-platform":
            return json(platformDocument);
          case "/list":
            return json({
              count: status === "missing" ? "0" : "1",
              total: status === "missing" ? "0" : "1",
              data: status === "missing" ? [] : [platformIdentity]
            });
          case "/identities/123/sign":
            return json({
              status: "completed",
              client_assertion: "a.b.c",
              agent_did: identity.agentDid,
              service_did: identity.serviceDid,
              issued_at: "2026-01-01T00:00:00Z",
              expires_at: expires,
              jti: "test"
            });
          case "/aep/status":
            return json({ status, since: "2026-01-01T00:00:00Z" });
          case "/aep/grant":
            return json(apiCredential);
          default:
            throw new Error(`Unexpected request: ${String(url)}`);
        }
      };
      vi.stubGlobal("fetch", fetch);
      const client = agent(fetch, {
        identityStore,
        credentialStore,
        identityProvider: createPlatformIdentityProvider({
          platformUrl: "https://platform.example"
        })
      });
      const session = client.serviceSession({ serviceUrl: "https://api.example.com" });
      if (status === "active") {
        await expect(session.grant()).resolves.toMatchObject({ body: apiCredential });
        expect(await credentialStore.listCredentials(identity.serviceDid)).toHaveLength(1);
        await session.grant();
        expect(paths.filter((path) => path === "/list")).toHaveLength(1);
        expect(paths.filter((path) => path === "/aep/status")).toHaveLength(1);
      } else {
        await expect(session.grant()).rejects.toMatchObject({
          problem: { code: "not_recognized" }
        });
        expect(paths).not.toContain("/aep/grant");
        expect(await credentialStore.listCredentials(identity.serviceDid)).toHaveLength(0);
      }
      expect(paths).not.toContain("/provision");
      expect(await identityStore.findByServiceDid(identity.serviceDid)).toEqual(
        status === "missing"
          ? undefined
          : expect.objectContaining({
              agentDid: identity.agentDid,
              identityKind: "platform-hosted"
            })
      );
    }
  );
});

describe("Platform credential boundaries", () => {
  it.each([false, true])(
    "authenticates provider list, provision and sign with a custom key=%s",
    async (customKey) => {
      const paths: string[] = [];
      vi.stubGlobal("fetch", async (input: URL | string, init?: RequestInit) => {
        const path = new URL(input).pathname;
        if (path === "/.well-known/aep-platform")
          return json(platformDocument, { "cache-control": "max-age=300" });
        paths.push(path);
        expect(new Headers(init?.headers).get("x-platform-key")).toBe("platform-secret");
        if (path === "/list") return json({ count: "0", total: "0", data: [] });
        if (path === "/provision") {
          const idempotencyKey = new Headers(init?.headers).get("idempotency-key");
          expect(idempotencyKey).toEqual(customKey ? "provision-key" : expect.any(String));
          expect(idempotencyKey?.length).toBeGreaterThan(0);
          return json(platformIdentity);
        }
        expect(path).toBe("/identities/123/sign");
        return json({
          status: "completed",
          client_assertion: "a.b.c",
          agent_did: identity.agentDid,
          service_did: identity.serviceDid,
          issued_at: "2026-01-01T00:00:00Z",
          expires_at: expires,
          jti: "test"
        });
      });
      const provider = createPlatformIdentityProvider({
        platformUrl: "https://platform.example",
        authenticationHeaders: () => ({ "X-Platform-Key": "platform-secret" }),
        ...(customKey ? { idempotencyKey: () => "provision-key" } : {})
      });
      const recovered = await provider.getOrCreateIdentity({
        inspect: document,
        serviceDid: identity.serviceDid,
        serviceUrl: "https://api.example.com"
      });
      const delegated = await provider.signerFor(recovered);
      await expect(delegated(claims, context)).resolves.toEqual({
        status: "completed",
        clientAssertion: "a.b.c"
      });
      expect(paths).toEqual(["/list", "/provision", "/identities/123/sign"]);
    }
  );

  it("forwards resource signing context, cancellation, and pending continuation metadata", async () => {
    const cache = createInMemoryPublicDocumentCache();
    const signal = new AbortController().signal;
    let signs = 0;
    const requests: RequestInit[] = [];
    vi.stubGlobal("fetch", async (input: URL | string, init?: RequestInit) => {
      if (String(input).endsWith("/.well-known/aep-platform")) {
        return json(platformDocument, { "cache-control": "max-age=300" });
      }
      requests.push(init ?? {});
      signs++;
      return json(
        signs === 1
          ? {
              status: "pending",
              retry_after_seconds: "5",
              platform_context: { approval: "approval-1" }
            }
          : {
              status: "completed",
              client_assertion: "signed.assertion.value",
              agent_did: identity.agentDid,
              service_did: identity.serviceDid,
              issued_at: "2026-01-01T00:00:00Z",
              expires_at: expires,
              jti: "test",
              platform_context: { approval: "approval-1", approved: true }
            }
      );
    });
    await discoverPlatform({
      platformUrl: new URL("https://platform.example"),
      publicDocumentCache: cache,
      signal,
      timeoutMs: 1000
    });
    const delegated = createPlatformDelegatedSigner({
      identity: platformIdentity,
      platformUrl: "https://platform.example",
      publicDocumentCache: cache,
      authenticationHeaders: { "X-Platform-Key": "secret" }
    });
    const resource = "https://api.example.com/orders";
    const pending = await delegated(
      { ...claims, op: "authenticate", resource },
      {
        ...context,
        command: "authenticate",
        signal,
        platformContext: { purpose: "read" }
      }
    );
    expect(pending).toEqual({
      status: "pending",
      retryAfterSeconds: 5,
      platformContext: { approval: "approval-1" }
    });
    const completed = await delegated(
      { ...claims, op: "authenticate", resource },
      {
        ...context,
        command: "authenticate",
        signal,
        platformContext: { approval: "approval-1" }
      }
    );
    expect(completed).toEqual({
      status: "completed",
      clientAssertion: "signed.assertion.value",
      platformContext: { approval: "approval-1", approved: true }
    });
    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(request.signal).toBe(signal);
      expect(new Headers(request.headers).get("x-platform-key")).toBe("secret");
      expect(requestJson(request.body)).toMatchObject({ op: "authenticate", resource });
    }
    expect(requestJson(requests[0]?.body)).toMatchObject({
      platform_context: { purpose: "read" }
    });
    expect(requestJson(requests[1]?.body)).toMatchObject({
      platform_context: { approval: "approval-1" }
    });
  });

  it.each(["provision", "list", "sign"])(
    "does not follow a %s redirect with custom credentials",
    async (operation) => {
      let received = 0;
      const receiver = createServer((_request, response) => {
        received++;
        response.end();
      });
      receiver.listen(0, "127.0.0.1");
      await once(receiver, "listening");
      const address = receiver.address();
      if (address === null || typeof address === "string") throw new Error("missing listener");
      const platform = createServer((request, response) => {
        request.resume();
        if (request.url === "/.well-known/aep-platform") {
          response.writeHead(200, { "content-type": AEP_MEDIA_TYPE });
          response.end(JSON.stringify(platformDocument));
        } else {
          response.writeHead(307, { location: `http://127.0.0.1:${address.port}/stolen` });
          response.end();
        }
      });
      try {
        platform.listen(0, "127.0.0.1");
        await once(platform, "listening");
        const source = platform.address();
        if (source === null || typeof source === "string") throw new Error("missing listener");
        const options = {
          platformUrl: `http://127.0.0.1:${source.port}`,
          authenticationHeaders: { "X-Platform-Key": "test-secret" }
        };
        const call =
          operation === "provision"
            ? provisionPlatformIdentity({
                ...options,
                idempotencyKey: "test",
                serviceDid: identity.serviceDid
              })
            : operation === "list"
              ? listPlatformIdentities(options)
              : createPlatformDelegatedSigner({ ...options, identity: platformIdentity })(
                  claims,
                  context
                );
        await expect(call).rejects.toThrow();
        expect(received).toBe(0);
      } finally {
        await Promise.all([
          new Promise<void>((resolve) => platform.close(() => resolve())),
          new Promise<void>((resolve) => receiver.close(() => resolve()))
        ]);
      }
    }
  );

  it("rejects discovery endpoints on another origin before resolving credentials", async () => {
    vi.stubGlobal("fetch", async () =>
      json({
        ...platformDocument,
        endpoints: { ...platformDocument.endpoints, list: "//other.example/list" }
      })
    );
    const authenticationHeaders = vi.fn(() => ({ "X-Key": "secret" }));
    await expect(
      listPlatformIdentities({ platformUrl: "https://platform.example", authenticationHeaders })
    ).rejects.toThrow("configured Platform origin");
    expect(authenticationHeaders).not.toHaveBeenCalled();
  });

  it.each(["no-store", "no-cache", "max-age=0", "max-age=300"])(
    "honors discovery %s on repeated provider calls",
    async (cacheControl) => {
      let discoveries = 0;
      vi.stubGlobal("fetch", async (input: URL | string) => {
        if (String(input).endsWith("/.well-known/aep-platform")) {
          discoveries++;
          return json(platformDocument, { "cache-control": cacheControl });
        }
        return json({ count: "1", total: "1", data: [platformIdentity] });
      });
      const provider = createPlatformIdentityProvider({
        platformUrl: "https://platform.example",
        publicDocumentCache: createInMemoryPublicDocumentCache()
      });
      await provider.findIdentityByServiceDid(identity.serviceDid);
      await provider.findIdentityByServiceDid(identity.serviceDid);
      expect(discoveries).toBe(cacheControl === "max-age=300" ? 1 : 2);
    }
  );

  it("retries failed discovery and refreshes discovery when a retained signer is used", async () => {
    let discoveries = 0;
    const paths: string[] = [];
    vi.stubGlobal("fetch", async (input: URL | string) => {
      const url = new URL(input);
      if (url.pathname === "/.well-known/aep-platform") {
        discoveries++;
        if (discoveries === 1) throw new Error("offline");
        return json(
          {
            ...platformDocument,
            endpoints: {
              ...platformDocument.endpoints,
              sign: `/sign-${discoveries}/{agent_identity_id}`
            }
          },
          { "cache-control": "no-store" }
        );
      }
      if (url.pathname === "/list")
        return json({ count: "1", total: "1", data: [platformIdentity] });
      paths.push(url.pathname);
      return json({
        status: "completed",
        client_assertion: "a.b.c",
        agent_did: identity.agentDid,
        service_did: identity.serviceDid,
        issued_at: "2026-01-01T00:00:00Z",
        expires_at: expires,
        jti: "test"
      });
    });
    const provider = createPlatformIdentityProvider({ platformUrl: "https://platform.example" });
    await expect(provider.findIdentityByServiceDid(identity.serviceDid)).rejects.toThrow();
    const found = await provider.findIdentityByServiceDid(identity.serviceDid);
    if (found === undefined) throw new Error("identity missing");
    const delegated = await provider.signerFor(found);
    await delegated(claims, context);
    await delegated(claims, context);
    expect(paths).toEqual(["/sign-3/123", "/sign-4/123"]);
  });
});
