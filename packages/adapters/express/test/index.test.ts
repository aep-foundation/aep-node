import { describe, expect, it } from "vitest";

import express from "express";

import { didWebIdentityMethod } from "@aep-foundation/service";

import {
  AEP_EXPRESS_MEDIA_TYPE,
  AEP_EXPRESS_WELL_KNOWN_PATH,
  createExpressAepHandler,
  createExpressAepHandlers,
  createExpressAepProtectedResourceHandler,
  packageName,
  registerExpressAepRoute,
  registerExpressAepRoutes
} from "../src/index.js";
import type { ExpressAepHandler, ExpressAepResponse } from "../src/index.js";
import type { AepService } from "@aep-foundation/service";

describe("@aep-foundation/express", () => {
  it("exports the package name", () => {
    expect(packageName).toBe("@aep-foundation/express");
  });

  it("creates an Inspect handler", () => {
    const handler = createExpressAepHandler({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });
    const response = createResponse();

    handler({ method: "GET" }, response);

    expect(response.statusCode).toBe(200);
    expect(response.contentType).toBe(AEP_EXPRESS_MEDIA_TYPE);
    expect(response.body).toMatchObject({
      aep_version: "1.0",
      service: {
        did: "did:web:service.example"
      }
    });
  });

  it("registers the well-known route on a router", () => {
    const routes: Array<{ handler: ExpressAepHandler; path: string }> = [];
    const router = {
      get(path: string, handler: ExpressAepHandler): void {
        routes.push({ handler, path });
      }
    };

    const result = registerExpressAepRoute(router, {
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });

    expect(result).toBe(router);
    expect(routes).toHaveLength(1);
    expect(routes[0]?.path).toBe(AEP_EXPRESS_WELL_KNOWN_PATH);
  });

  it("registers Inspect and command routes on a router", () => {
    const routes: Array<{ method: string; path: string }> = [];
    const router = {
      get(path: string): void {
        routes.push({ method: "GET", path });
      },
      post(path: string): void {
        routes.push({ method: "POST", path });
      }
    };

    registerExpressAepRoutes(router, {
      grantTypes: [{ grantType: "oauth-bearer" }],
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });

    expect(routes).toEqual([
      { method: "GET", path: "/.well-known/aep" },
      { method: "POST", path: "/aep/enroll" },
      { method: "GET", path: "/aep/status" },
      { method: "POST", path: "/aep/grant" },
      { method: "POST", path: "/aep/revoke" }
    ]);
  });

  it("passes command bodies and client assertions to the Service", async () => {
    const calls: Array<{ body: unknown; clientAssertion: string }> = [];
    const handlers = createExpressAepHandlers({
      ...mockService(),
      enroll: (body, options) => {
        calls.push({ body, clientAssertion: options.clientAssertion });
        return Promise.resolve({
          body: { status: "active" },
          contentType: "application/aep+json",
          status: 200
        });
      }
    });
    const response = createResponse();

    await handlers.enroll(
      {
        body: {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "idem"
        },
        headers: {
          authorization: "AEP signed.jwt"
        },
        method: "POST"
      },
      response
    );

    expect(calls).toEqual([
      {
        body: {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "idem"
        },
        clientAssertion: "signed.jwt"
      }
    ]);
    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual({ status: "active" });
  });

  it("handles Inspect and command requests through a real Express app", async () => {
    const calls: Array<{ body: unknown; clientAssertion: string }> = [];
    const app = express() as express.Express & ExpressDispatchApp;

    app.use(express.json({ type: "application/aep+json" }));
    registerExpressAepRoutes(app, {
      ...mockService(),
      grant: (body, options) => {
        calls.push({ body, clientAssertion: options.clientAssertion });
        return Promise.resolve({
          body: {
            credential_id: "cred_123"
          },
          contentType: "application/aep+json",
          status: 200
        });
      }
    });

    const inspect = await dispatchExpress(app, "GET", "/.well-known/aep");
    expect(inspect.status).toBe(200);
    expect(inspect.headers["content-type"]).toContain("application/aep+json");
    expect(inspect.body).toMatchObject({
      service: {
        did: "did:web:service.example"
      }
    });

    const grant = await dispatchExpress(
      app,
      "POST",
      "/aep/grant",
      {
        authorization: "AEP signed.jwt"
      },
      {
        grant_type: "oauth-bearer"
      }
    );

    expect(grant.status).toBe(200);
    expect(grant.headers["content-type"]).toContain("application/aep+json");
    expect(grant.body).toEqual({
      credential_id: "cred_123"
    });
    expect(calls).toEqual([
      {
        body: {
          grant_type: "oauth-bearer"
        },
        clientAssertion: "signed.jwt"
      }
    ]);
  });

  it("returns method errors for non-GET requests", () => {
    const handler = createExpressAepHandler({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });
    const response = createResponse();

    handler({ method: "POST" }, response);

    expect(response.headers["Allow"]).toBe("GET");
    expect(response.statusCode).toBe(405);
    expect(response.body).toMatchObject({
      status: 405,
      title: "Method Not Allowed"
    });
  });

  it("adapts protected-resource failures and authenticated continuations", async () => {
    const response = createResponse();
    const denied = createExpressAepProtectedResourceHandler(mockService(), "https://api.example");
    await denied({ headers: {}, method: "GET", originalUrl: "/orders" }, response);
    expect(response.statusCode).toBe(401);
    expect(response.contentType).toBe("application/problem+json");

    let continued = false;
    const allowed = createExpressAepProtectedResourceHandler(
      {
        ...mockService(),
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
      "https://api.example"
    );
    await allowed({}, createResponse(), () => {
      continued = true;
    });
    expect(continued).toBe(true);
  });
});

interface CapturedResponse extends ExpressAepResponse {
  body?: unknown;
  contentType?: string;
  headers: Record<string, string>;
  statusCode?: number;
}

function mockService(): AepService {
  return {
    authenticateProtectedResource: () =>
      Promise.resolve({
        authenticated: false,
        response: {
          body: {
            type: "urn:aep:error:authentication_required",
            title: "Authentication required",
            status: 401,
            code: "authentication_required"
          },
          contentType: "application/problem+json",
          status: 401
        }
      }),
    enroll: () =>
      Promise.resolve({
        body: { status: "active" },
        contentType: "application/aep+json",
        status: 200
      }),
    grant: () =>
      Promise.resolve({
        body: {},
        contentType: "application/aep+json",
        status: 200
      }),
    inspectDocument: () => ({
      aep_version: "1.0",
      bindings: { supported: ["http"] },
      commands: {
        grant_types: ["oauth-bearer"],
        supported: ["enroll", "grant", "inspect", "revoke", "status"]
      },
      core: { signing_algorithms: ["EdDSA", "ES256"] },
      http: { endpoint_base: "/aep/" },
      identity: { methods: ["did:web"] },
      service: { did: "did:web:service.example" }
    }),
    revoke: () =>
      Promise.resolve({
        body: {},
        contentType: "application/aep+json",
        status: 200
      }),
    status: () =>
      Promise.resolve({
        body: {
          owner_action_required: "false",
          requirements_pending: [],
          since: "2026-05-28T12:00:00.000Z",
          status: "active"
        },
        contentType: "application/aep+json",
        status: 200
      })
  };
}

function dispatchExpress(
  app: ExpressDispatchApp,
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: unknown
): Promise<{
  body: unknown;
  headers: Record<string, string>;
  status: number;
}> {
  return new Promise((resolve, reject) => {
    const response = {
      headers: {} as Record<string, string>,
      statusCode: 200,
      end(payload?: string | Buffer) {
        const raw = payload?.toString() ?? "";
        resolve({
          body: raw.length > 0 ? JSON.parse(raw) : undefined,
          headers: this.headers,
          status: this.statusCode
        });
      },
      getHeader(name: string) {
        return this.headers[name.toLowerCase()];
      },
      setHeader(name: string, value: number | string | string[]) {
        this.headers[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
      }
    };

    app.handle(
      {
        body,
        headers,
        method,
        url
      } as never,
      response as never,
      reject
    );
  });
}

interface ExpressDispatchApp {
  handle(request: never, response: never, next: (error?: unknown) => void): void;
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
