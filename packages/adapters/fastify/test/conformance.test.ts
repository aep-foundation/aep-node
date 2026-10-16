import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signClientAssertionJwt } from "@aep-foundation/core";
import {
  createAepService,
  createJwtClientAssertionVerifier,
  didWebIdentityMethod
} from "@aep-foundation/service";

import {
  AEP_FASTIFY_PROBLEM_MEDIA_TYPE,
  createFastifyAepHandler,
  createFastifyAepHandlers,
  createFastifyAepProtectedResourceHandler
} from "../src/index.js";
import type { FastifyAepReply, FastifyAepRequest } from "../src/index.js";
import type {
  AepAuthenticatedServiceOptions,
  AepIdempotentServiceOptions,
  AepService
} from "@aep-foundation/service";

interface CapturedReply extends FastifyAepReply {
  body?: unknown;
  contentType?: string;
  headers: Record<string, string>;
  statusCode?: number;
}

interface CapturedCall {
  body?: unknown;
  clientAssertion: string;
  command: string;
  idempotencyKey?: string;
}

function createReply(): CapturedReply {
  return {
    headers: {},
    header(name: string, value: string) {
      this.headers[name] = value;
      return this;
    },
    send(body: unknown) {
      this.body = body;
      return this;
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    type(contentType: string) {
      this.contentType = contentType;
      return this;
    }
  };
}

function recordingService(calls: CapturedCall[]): AepService {
  const respond = (command: string) =>
    Promise.resolve({
      body: { command },
      contentType: "application/aep+json",
      headers: { "X-Adapter": command },
      status: 200
    });

  return {
    authenticateProtectedResource: () =>
      Promise.resolve({
        authenticated: false,
        response: {
          body: {
            code: "authentication_required",
            status: 401,
            title: "Authentication required",
            type: "urn:aep:error:authentication_required"
          },
          contentType: "application/problem+json",
          headers: { "WWW-Authenticate": 'AEP service_did="did:web:api.example"' },
          status: 401
        }
      }),
    enroll: (body: unknown, options: AepIdempotentServiceOptions) => {
      calls.push({ body, command: "enroll", ...options });
      return respond("enroll");
    },
    grant: (body: unknown, options: AepIdempotentServiceOptions) => {
      calls.push({ body, command: "grant", ...options });
      return respond("grant");
    },
    inspectDocument: () => ({}) as never,
    revoke: (body: unknown, options: AepIdempotentServiceOptions) => {
      calls.push({ body, command: "revoke", ...options });
      return respond("revoke");
    },
    status: (options: AepAuthenticatedServiceOptions) => {
      calls.push({ command: "status", ...options });
      return respond("status");
    }
  } as unknown as AepService;
}

async function runCommand(
  command: "enroll" | "grant" | "revoke" | "status",
  request: FastifyAepRequest
): Promise<{ calls: CapturedCall[]; reply: CapturedReply }> {
  const calls: CapturedCall[] = [];
  const handlers = createFastifyAepHandlers(recordingService(calls));
  const reply = createReply();

  await handlers[command](request, reply);
  return { calls, reply };
}

describe("fastify command dispatch", () => {
  it("routes each command to its Service method and echoes the response envelope", async () => {
    for (const command of ["enroll", "grant", "revoke", "status"] as const) {
      const { calls, reply } = await runCommand(command, {
        body: { field: command },
        headers: { authorization: "AEP header.payload.signature", "idempotency-key": "key-1" }
      });

      expect(calls).toHaveLength(1);
      expect(calls[0]?.command).toBe(command);
      expect(calls[0]?.clientAssertion).toBe("header.payload.signature");
      expect(reply.statusCode).toBe(200);
      expect(reply.contentType).toBe("application/aep+json");
      expect(reply.headers["X-Adapter"]).toBe(command);
      expect(reply.body).toEqual({ command });
    }
  });

  it("carries the idempotency key on state-mutating commands only", async () => {
    for (const command of ["enroll", "grant", "revoke"] as const) {
      const { calls } = await runCommand(command, {
        body: {},
        headers: { authorization: "AEP a.b.c", "idempotency-key": "key-1" }
      });

      expect(calls[0]?.idempotencyKey).toBe("key-1");
    }

    const { calls } = await runCommand("status", {
      headers: { authorization: "AEP a.b.c", "idempotency-key": "key-1" }
    });

    expect(calls[0]?.idempotencyKey).toBeUndefined();
  });

  it("works when the request carries no headers", async () => {
    const { calls } = await runCommand("enroll", { body: {} });

    expect(calls[0]?.clientAssertion).toBe("");
    expect(calls[0]?.idempotencyKey).toBe("");
  });
});

describe("fastify Authorization field handling", () => {
  it("accepts a case-insensitive scheme separated by one or more spaces", async () => {
    for (const authorization of [
      "AEP header.payload.signature",
      "aep header.payload.signature",
      "AEP   header.payload.signature",
      "AEP\theader.payload.signature",
      "AEP header.payload.signature  "
    ]) {
      const { calls } = await runCommand("enroll", { body: {}, headers: { authorization } });

      expect(calls[0]?.clientAssertion, authorization).toBe("header.payload.signature");
    }
  });

  it("presents no assertion when the field is absent, empty, or not an AEP credential", async () => {
    for (const headers of [
      {},
      { authorization: "" },
      { authorization: "AEP" },
      { authorization: "Bearer opaque-token" },
      { authorization: "Payment mpp-credential" },
      { authorization: "AEP a b" }
    ]) {
      const { calls } = await runCommand("enroll", { body: {}, headers });

      expect(calls[0]?.clientAssertion, JSON.stringify(headers)).toBe("");
    }
  });

  it("presents no assertion when the field repeats or duplicate lines were joined", async () => {
    const repeated = await runCommand("enroll", {
      body: {},
      headers: { authorization: ["AEP first.a.a", "AEP second.b.b"] }
    });
    expect(repeated.calls[0]?.clientAssertion).toBe("");

    const joined = await runCommand("enroll", {
      body: {},
      headers: { authorization: "AEP first.a.a, AEP second.b.b" }
    });
    expect(joined.calls[0]?.clientAssertion).toBe("");
  });

  it("accepts a single-element field array", async () => {
    const { calls } = await runCommand("enroll", {
      body: {},
      headers: { authorization: ["AEP only.a.a"] }
    });

    expect(calls[0]?.clientAssertion).toBe("only.a.a");
  });
});

describe("fastify Idempotency-Key field handling", () => {
  it("presents no key when the field is absent or repeats", async () => {
    const absent = await runCommand("enroll", { body: {}, headers: {} });
    expect(absent.calls[0]?.idempotencyKey).toBe("");

    const repeated = await runCommand("enroll", {
      body: {},
      headers: { "idempotency-key": ["key-1", "key-2"] }
    });
    expect(repeated.calls[0]?.idempotencyKey).toBe("");
  });

  it("accepts a single-element array", async () => {
    const { calls } = await runCommand("enroll", {
      body: {},
      headers: { "idempotency-key": ["key-1"] }
    });

    expect(calls[0]?.idempotencyKey).toBe("key-1");
  });
});

describe("fastify Inspect method guard", () => {
  it("answers a non-GET request with conformant Problem Details", () => {
    const handler = createFastifyAepHandler({ inspectDocument: () => ({}) } as never);
    const reply = createReply();

    handler({ method: "POST" }, reply);

    expect(reply.statusCode).toBe(405);
    expect(reply.headers["Allow"]).toBe("GET");
    expect(reply.contentType).toBe(AEP_FASTIFY_PROBLEM_MEDIA_TYPE);
    expect(reply.body).toEqual({
      code: "invalid_request",
      detail: "AEP Inspect only supports GET requests.",
      status: 405,
      title: "Method Not Allowed",
      type: "urn:aep:error:invalid_request"
    });
  });

  it("serves the document for GET and when the method is absent", () => {
    const handler = createFastifyAepHandler({
      inspectDocument: () => ({ aep_version: "1.0" })
    } as never);

    const explicit = createReply();
    handler({ method: "GET" }, explicit);
    expect(explicit.statusCode).toBe(200);
    expect(explicit.body).toEqual({ aep_version: "1.0" });

    const implicit = createReply();
    handler({}, implicit);
    expect(implicit.statusCode).toBe(200);
    expect(implicit.body).toEqual({ aep_version: "1.0" });
  });

  it("works when the reply exposes only type and send", () => {
    const handler = createFastifyAepHandler({
      inspectDocument: () => ({ aep_version: "1.0" })
    } as never);
    let captured: unknown;
    const minimal: FastifyAepReply = {
      send(body: unknown) {
        captured = body;
        return this;
      },
      type() {
        return this;
      }
    };

    handler({ method: "GET" }, minimal);
    expect(captured).toEqual({ aep_version: "1.0" });

    handler({ method: "DELETE" }, minimal);
    expect(captured).toMatchObject({ code: "invalid_request", status: 405 });
  });
});

describe("fastify protected-resource target resolution", () => {
  it.each([
    "/a/..//evil.example/orders",
    "/a/%2e%2e//evil.example/orders",
    "https://api.example.com//evil.example/orders"
  ])("verifies the signed resource against the configured origin for %s", async (target) => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const service = createAepService({
      serviceDid: "did:web:api.example.com",
      authenticationMethods: ["aep-jwt"],
      identityMethods: [didWebIdentityMethod()],
      clientAssertionVerifier: createJwtClientAssertionVerifier({ key: publicKey })
    });
    const handler = createFastifyAepProtectedResourceHandler(service, "https://api.example.com");
    for (const resource of [
      "https://evil.example/orders",
      "https://api.example.com//evil.example/orders"
    ]) {
      const iat = Math.floor(Date.now() / 1000);
      const token = await signClientAssertionJwt(
        {
          iss: "did:web:agent.example",
          sub: "did:web:agent.example",
          aud: "did:web:api.example.com",
          op: "authenticate",
          resource,
          iat,
          exp: iat + 300,
          jti: resource
        },
        { alg: "EdDSA", key: privateKey }
      );
      const response = createReply();
      await handler(
        {
          url: target,
          method: "GET",
          headers: { authorization: `AEP ${token}` }
        },
        response
      );
      if (resource.startsWith("https://evil.example/")) {
        expect(response.statusCode).toBe(401);
        expect(response.body).toMatchObject({ code: "not_recognized" });
      } else {
        expect(response.statusCode).toBeUndefined();
      }
    }
  });
  async function resolvedUrl(url: string | undefined): Promise<string> {
    let seen = "";
    const service = {
      inspectDocument: () => ({}),
      authenticateProtectedResource: (options: { url: URL }) => {
        seen = String(options.url);
        return Promise.resolve({
          authenticated: true,
          principal: {
            agentDid: "did:web:agent.example",
            authenticationKind: "aep-jwt",
            authenticationMethod: "aep-jwt"
          }
        });
      }
    } as unknown as AepService;
    const handler = createFastifyAepProtectedResourceHandler(service, "https://api.example.com");

    await handler(
      { headers: {}, method: "GET", ...(url === undefined ? {} : { url }) },
      createReply()
    );

    return seen;
  }

  it("keeps only the path and query of the request target", async () => {
    expect(await resolvedUrl("/v1/orders/123")).toBe("https://api.example.com/v1/orders/123");
    expect(await resolvedUrl("/v1/orders?view=full")).toBe(
      "https://api.example.com/v1/orders?view=full"
    );
    expect(await resolvedUrl(undefined)).toBe("https://api.example.com/");
  });

  it("never lets an absolute or protocol-relative target move the origin", async () => {
    expect(await resolvedUrl("https://evil.example/steal")).toBe("https://api.example.com/steal");
    expect(await resolvedUrl("//evil.example/steal")).toBe(
      "https://api.example.com//evil.example/steal"
    );
  });
});

describe("fastify protected-resource rejection", () => {
  it("copies the challenge headers and Problem Details onto the reply", async () => {
    const calls: CapturedCall[] = [];
    const handler = createFastifyAepProtectedResourceHandler(
      recordingService(calls),
      "https://api.example.com"
    );
    const reply = createReply();

    await handler({ headers: {}, method: "GET", url: "/orders" }, reply);

    expect(reply.statusCode).toBe(401);
    expect(reply.contentType).toBe("application/problem+json");
    expect(reply.headers["WWW-Authenticate"]).toBe('AEP service_did="did:web:api.example"');
    expect(reply.body).toMatchObject({ code: "authentication_required" });
  });

  it("returns nothing when authentication succeeds so the route handler runs", async () => {
    const service = {
      inspectDocument: () => ({}),
      authenticateProtectedResource: () =>
        Promise.resolve({
          authenticated: true,
          principal: {
            agentDid: "did:web:agent.example",
            authenticationKind: "aep-jwt",
            authenticationMethod: "aep-jwt"
          }
        })
    } as unknown as AepService;
    const handler = createFastifyAepProtectedResourceHandler(service, "https://api.example.com");

    await expect(
      handler({ headers: {}, method: "GET", url: "/orders" }, createReply())
    ).resolves.toBeUndefined();
  });

  it("works when the reply exposes no header or status helpers", async () => {
    const calls: CapturedCall[] = [];
    const handler = createFastifyAepProtectedResourceHandler(
      recordingService(calls),
      "https://api.example.com"
    );
    let captured: unknown;
    const minimal: FastifyAepReply = {
      send(body: unknown) {
        captured = body;
        return this;
      },
      type() {
        return this;
      }
    };

    await handler({ headers: {}, method: "GET", url: "/orders" }, minimal);

    expect(captured).toMatchObject({ code: "authentication_required" });
  });
});

describe("fastify minimal reply objects", () => {
  it("dispatches a command when the reply exposes only type and send", async () => {
    const calls: CapturedCall[] = [];
    const handlers = createFastifyAepHandlers(recordingService(calls));
    let captured: unknown;
    const minimal: FastifyAepReply = {
      send(body: unknown) {
        captured = body;
        return this;
      },
      type() {
        return this;
      }
    };

    await handlers.enroll({ body: {}, headers: {} }, minimal);

    expect(captured).toEqual({ command: "enroll" });
  });
});
