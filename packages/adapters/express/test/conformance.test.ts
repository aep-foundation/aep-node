import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signClientAssertionJwt } from "@aep-foundation/core";
import {
  createAepService,
  createJwtClientAssertionVerifier,
  didWebIdentityMethod
} from "@aep-foundation/service";

import {
  AEP_EXPRESS_PROBLEM_MEDIA_TYPE,
  createExpressAepHandler,
  createExpressAepHandlers,
  createExpressAepProtectedResourceHandler
} from "../src/index.js";
import type { ExpressAepRequest, ExpressAepResponse } from "../src/index.js";
import type {
  AepAuthenticatedServiceOptions,
  AepIdempotentServiceOptions,
  AepService
} from "@aep-foundation/service";

interface CapturedResponse extends ExpressAepResponse {
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

function createResponse(): CapturedResponse {
  return {
    headers: {},
    json(body: unknown) {
      this.body = body;
      return this;
    },
    set(field: string, value: string) {
      this.headers[field] = value;
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
      headers: { "Idempotency-Key": "echoed", "X-Adapter": command },
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
  request: ExpressAepRequest
): Promise<{ calls: CapturedCall[]; response: CapturedResponse }> {
  const calls: CapturedCall[] = [];
  const handlers = createExpressAepHandlers(recordingService(calls));
  const response = createResponse();

  await handlers[command](request, response);
  return { calls, response };
}

describe("express command dispatch", () => {
  it("routes each command to its Service method and echoes the response envelope", async () => {
    for (const command of ["enroll", "grant", "revoke", "status"] as const) {
      const { calls, response } = await runCommand(command, {
        body: { field: command },
        headers: { authorization: "AEP header.payload.signature", "idempotency-key": "key-1" }
      });

      expect(calls).toHaveLength(1);
      expect(calls[0]?.command).toBe(command);
      expect(calls[0]?.clientAssertion).toBe("header.payload.signature");
      expect(response.statusCode).toBe(200);
      expect(response.contentType).toBe("application/aep+json");
      expect(response.headers["X-Adapter"]).toBe(command);
      expect(response.body).toEqual({ command });
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
});

describe("express Authorization field handling", () => {
  it("accepts a case-insensitive scheme separated by one or more spaces", async () => {
    for (const authorization of [
      "AEP header.payload.signature",
      "aep header.payload.signature",
      "AeP header.payload.signature",
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
      { authorization: "AEP " },
      { authorization: "Bearer opaque-token" },
      { authorization: "Basic dXNlcjpwYXNz" },
      { authorization: "Payment mpp-credential" },
      { authorization: "AEP a b" }
    ]) {
      const { calls } = await runCommand("enroll", { body: {}, headers });

      expect(calls[0]?.clientAssertion, JSON.stringify(headers)).toBe("");
    }
  });

  it("presents no assertion when the field repeats", async () => {
    const { calls } = await runCommand("enroll", {
      body: {},
      headers: { authorization: ["AEP first.a.a", "AEP second.b.b"] }
    });

    expect(calls[0]?.clientAssertion).toBe("");
  });

  it("presents no assertion when duplicate field lines were joined", async () => {
    const { calls } = await runCommand("enroll", {
      body: {},
      headers: { authorization: "AEP first.a.a, AEP second.b.b" }
    });

    expect(calls[0]?.clientAssertion).toBe("");
  });

  it("accepts a single-element field array", async () => {
    const { calls } = await runCommand("enroll", {
      body: {},
      headers: { authorization: ["AEP only.a.a"] }
    });

    expect(calls[0]?.clientAssertion).toBe("only.a.a");
  });

  it("falls back to the framework field accessors when no raw headers are present", async () => {
    const viaGet = await runCommand("enroll", {
      body: {},
      get: (field) => (field === "Authorization" ? "AEP from.get.value" : undefined)
    });
    expect(viaGet.calls[0]?.clientAssertion).toBe("from.get.value");

    const viaHeader = await runCommand("enroll", {
      body: {},
      header: (field) => (field === "Authorization" ? "AEP from.header.value" : undefined)
    });
    expect(viaHeader.calls[0]?.clientAssertion).toBe("from.header.value");
  });

  it("reads a capitalized raw field name", async () => {
    const { calls } = await runCommand("enroll", {
      body: {},
      headers: { Authorization: "AEP capitalized.a.a" }
    });

    expect(calls[0]?.clientAssertion).toBe("capitalized.a.a");
  });
});

describe("express Idempotency-Key field handling", () => {
  it("presents no key when the field is absent or repeats", async () => {
    const absent = await runCommand("enroll", { body: {}, headers: {} });
    expect(absent.calls[0]?.idempotencyKey).toBe("");

    const repeated = await runCommand("enroll", {
      body: {},
      headers: { "idempotency-key": ["key-1", "key-2"] }
    });
    expect(repeated.calls[0]?.idempotencyKey).toBe("");
  });

  it("accepts a single-element array and a capitalized raw field name", async () => {
    const array = await runCommand("enroll", {
      body: {},
      headers: { "idempotency-key": ["key-1"] }
    });
    expect(array.calls[0]?.idempotencyKey).toBe("key-1");

    const capitalized = await runCommand("enroll", {
      body: {},
      headers: { "Idempotency-Key": "key-2" }
    });
    expect(capitalized.calls[0]?.idempotencyKey).toBe("key-2");
  });

  it("falls back to the framework field accessors", async () => {
    const viaGet = await runCommand("enroll", {
      body: {},
      get: (field) => (field === "Idempotency-Key" ? "key-get" : undefined)
    });
    expect(viaGet.calls[0]?.idempotencyKey).toBe("key-get");

    const viaHeader = await runCommand("enroll", {
      body: {},
      header: (field) => (field === "Idempotency-Key" ? "key-header" : undefined)
    });
    expect(viaHeader.calls[0]?.idempotencyKey).toBe("key-header");
  });
});

describe("express Inspect method guard", () => {
  it("answers a non-GET request with conformant Problem Details", () => {
    const handler = createExpressAepHandler({ inspectDocument: () => ({}) } as never);
    const response = createResponse();

    handler({ method: "POST" }, response);

    expect(response.statusCode).toBe(405);
    expect(response.headers["Allow"]).toBe("GET");
    expect(response.contentType).toBe(AEP_EXPRESS_PROBLEM_MEDIA_TYPE);
    expect(response.body).toEqual({
      code: "invalid_request",
      detail: "AEP Inspect only supports GET requests.",
      status: 405,
      title: "Method Not Allowed",
      type: "urn:aep:error:invalid_request"
    });
  });

  it("serves the document when the method is absent", () => {
    const handler = createExpressAepHandler({
      inspectDocument: () => ({ aep_version: "1.0" })
    } as never);
    const response = createResponse();

    handler({}, response);

    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual({ aep_version: "1.0" });
  });
});

describe("express protected-resource target resolution", () => {
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
    const handler = createExpressAepProtectedResourceHandler(service, "https://api.example.com");
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
      const response = createResponse();
      await handler(
        {
          originalUrl: target,
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
  async function resolvedUrl(originalUrl: string | undefined): Promise<string> {
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
    const handler = createExpressAepProtectedResourceHandler(service, "https://api.example.com");

    await handler(
      { headers: {}, method: "GET", ...(originalUrl === undefined ? {} : { originalUrl }) },
      createResponse(),
      () => undefined
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
    expect(await resolvedUrl("http://user:pass@evil.example/steal")).toBe(
      "https://api.example.com/steal"
    );
  });

  it("drops a fragment from the request target", async () => {
    expect(await resolvedUrl("/v1/orders#section")).toBe("https://api.example.com/v1/orders");
  });
});

describe("express protected-resource rejection", () => {
  it("copies the challenge headers and Problem Details onto the response", async () => {
    const calls: CapturedCall[] = [];
    const handler = createExpressAepProtectedResourceHandler(
      recordingService(calls),
      "https://api.example.com"
    );
    const response = createResponse();
    let continued = false;

    await handler({ headers: {}, method: "GET", originalUrl: "/orders" }, response, () => {
      continued = true;
    });

    expect(continued).toBe(false);
    expect(response.statusCode).toBe(401);
    expect(response.contentType).toBe("application/problem+json");
    expect(response.headers["WWW-Authenticate"]).toBe('AEP service_did="did:web:api.example"');
    expect(response.body).toMatchObject({ code: "authentication_required" });
  });

  it("continues without a next callback", async () => {
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
    const handler = createExpressAepProtectedResourceHandler(service, "https://api.example.com");

    await expect(
      handler({ headers: {}, method: "GET", originalUrl: "/orders" }, createResponse())
    ).resolves.toBeUndefined();
  });
});

describe("express minimal response objects", () => {
  it("works when the response exposes only json and status", async () => {
    const calls: CapturedCall[] = [];
    const handlers = createExpressAepHandlers(recordingService(calls));
    let captured: unknown;
    const minimal: ExpressAepResponse = {
      json(body: unknown) {
        captured = body;
        return this;
      },
      status() {
        return this;
      }
    };

    await handlers.enroll({ body: {}, headers: {} }, minimal);

    expect(captured).toEqual({ command: "enroll" });
  });
});
