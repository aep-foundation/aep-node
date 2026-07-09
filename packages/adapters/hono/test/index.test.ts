import { describe, expect, it } from "vitest";

import { Hono } from "hono";

import { didWebIdentityMethod } from "@aep-foundation/service";

import {
  AEP_HONO_MEDIA_TYPE,
  AEP_HONO_WELL_KNOWN_PATH,
  createHonoAepHandler,
  createHonoAepHandlers,
  packageName,
  registerHonoAepRoute,
  registerHonoAepRoutes
} from "../src/index.js";
import type { HonoAepContext, HonoAepHandler } from "../src/index.js";
import type { AepService } from "@aep-foundation/service";

describe("@aep-foundation/hono", () => {
  it("exports the package name", () => {
    expect(packageName).toBe("@aep-foundation/hono");
  });

  it("creates an Inspect handler", () => {
    const handler = createHonoAepHandler({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });
    const context = createContext();

    handler(context);

    expect(context.statusCode).toBe(200);
    expect(context.headers).toEqual({
      "Content-Type": AEP_HONO_MEDIA_TYPE
    });
    expect(context.body).toMatchObject({
      aep_version: "1.0",
      service: {
        did: "did:web:service.example"
      }
    });
  });

  it("registers the well-known route on an app", () => {
    const routes: Array<{ handler: HonoAepHandler; path: string }> = [];
    const app = {
      get(path: string, handler: HonoAepHandler): void {
        routes.push({ handler, path });
      }
    };

    const result = registerHonoAepRoute(app, {
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });

    expect(result).toBe(app);
    expect(routes).toHaveLength(1);
    expect(routes[0]?.path).toBe(AEP_HONO_WELL_KNOWN_PATH);
  });

  it("registers Inspect and command routes on an app", () => {
    const routes: Array<{ method: string; path: string }> = [];
    const app = {
      get(path: string): void {
        routes.push({ method: "GET", path });
      },
      post(path: string): void {
        routes.push({ method: "POST", path });
      }
    };

    registerHonoAepRoutes(app, {
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
    const handlers = createHonoAepHandlers({
      ...mockService(),
      revoke: (body, options) => {
        calls.push({ body, clientAssertion: options.clientAssertion });
        return Promise.resolve({
          body: {},
          contentType: "application/aep+json",
          status: 200
        });
      }
    });
    const context = createContext({
      body: {
        grant_type: "oauth-bearer"
      },
      authorization: "AEP signed.jwt"
    });

    await handlers.revoke(context);

    expect(calls).toEqual([
      {
        body: {
          grant_type: "oauth-bearer"
        },
        clientAssertion: "signed.jwt"
      }
    ]);
    expect(context.statusCode).toBe(200);
    expect(context.body).toEqual({});
  });

  it("handles Inspect and command requests through a real Hono app", async () => {
    const calls: Array<{ body: unknown; clientAssertion: string }> = [];
    const app = new Hono();

    registerHonoAepRoutes(app, {
      ...mockService(),
      revoke: (body, options) => {
        calls.push({ body, clientAssertion: options.clientAssertion });
        return Promise.resolve({
          body: {},
          contentType: "application/aep+json",
          status: 200
        });
      }
    });

    const inspect = await app.request("/.well-known/aep");
    expect(inspect.status).toBe(200);
    expect(inspect.headers.get("content-type")).toContain("application/aep+json");
    await expect(inspect.json()).resolves.toMatchObject({
      service: {
        did: "did:web:service.example"
      }
    });

    const revoke = await app.request("/aep/revoke", {
      body: JSON.stringify({
        grant_type: "oauth-bearer"
      }),
      headers: {
        Authorization: "AEP signed.jwt",
        "Content-Type": "application/aep+json"
      },
      method: "POST"
    });
    expect(revoke.status).toBe(200);
    expect(revoke.headers.get("content-type")).toContain("application/aep+json");
    await expect(revoke.json()).resolves.toEqual({});
    expect(calls).toEqual([
      {
        body: {
          grant_type: "oauth-bearer"
        },
        clientAssertion: "signed.jwt"
      }
    ]);
  });
});

interface CapturedContext extends HonoAepContext {
  body?: unknown;
  headers?: Record<string, string>;
  statusCode?: number;
}

function createContext(options: { authorization?: string; body?: unknown } = {}): CapturedContext {
  return {
    json(body: unknown, status?: number, headers?: Record<string, string>) {
      this.body = body;

      if (status !== undefined) {
        this.statusCode = status;
      }

      if (headers !== undefined) {
        this.headers = headers;
      }

      return new Response(JSON.stringify(body), {
        ...(headers === undefined ? {} : { headers }),
        ...(status === undefined ? {} : { status })
      });
    },
    req: {
      header(name: string) {
        return name.toLowerCase() === "authorization" ? options.authorization : undefined;
      },
      json: () => Promise.resolve(options.body)
    }
  };
}

function mockService(): AepService {
  return {
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
      core: {},
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
