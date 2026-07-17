import { describe, expect, it } from "vitest";

import fastify from "fastify";

import { didWebIdentityMethod } from "@aep-foundation/service";

import {
  AEP_FASTIFY_MEDIA_TYPE,
  AEP_FASTIFY_WELL_KNOWN_PATH,
  createFastifyAepHandler,
  createFastifyAepHandlers,
  createFastifyAepProtectedResourceHandler,
  createFastifyAepPlugin,
  createFastifyAepRoutesPlugin,
  packageName
} from "../src/index.js";
import type { FastifyAepHandler, FastifyAepReply } from "../src/index.js";
import type { AepService } from "@aep-foundation/service";

describe("@aep-foundation/fastify", () => {
  it("adapts protected-resource authentication", async () => {
    const reply = createReply();
    await createFastifyAepProtectedResourceHandler(mockService(), "https://api.example")(
      { headers: {}, method: "GET", url: "/orders" },
      reply
    );
    expect(reply.statusCode).toBe(401);
    expect(reply.contentType).toBe("application/problem+json");

    const allowed = createFastifyAepProtectedResourceHandler(
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
    await expect(allowed({}, createReply())).resolves.toBeUndefined();
  });

  it("exports the package name", () => {
    expect(packageName).toBe("@aep-foundation/fastify");
  });

  it("creates an Inspect handler", () => {
    const handler = createFastifyAepHandler({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });
    const reply = createReply();

    handler({}, reply);

    expect(reply.statusCode).toBe(200);
    expect(reply.contentType).toBe(AEP_FASTIFY_MEDIA_TYPE);
    expect(reply.body).toMatchObject({
      aep_version: "1.0",
      service: {
        did: "did:web:service.example"
      }
    });
  });

  it("registers the well-known route as a plugin", async () => {
    const routes: Array<{ handler: FastifyAepHandler; path: string }> = [];
    const plugin = createFastifyAepPlugin({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });

    await plugin({
      get(path: string, handler: FastifyAepHandler): void {
        routes.push({ handler, path });
      }
    });

    expect(routes).toHaveLength(1);
    expect(routes[0]?.path).toBe(AEP_FASTIFY_WELL_KNOWN_PATH);
  });

  it("registers Inspect and command routes as a plugin", async () => {
    const routes: Array<{ method: string; path: string }> = [];
    const plugin = createFastifyAepRoutesPlugin({
      grantTypes: [{ grantType: "oauth-bearer" }],
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });

    await plugin({
      get(path: string): void {
        routes.push({ method: "GET", path });
      },
      post(path: string): void {
        routes.push({ method: "POST", path });
      }
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
    const handlers = createFastifyAepHandlers({
      ...mockService(),
      grant: (body, options) => {
        calls.push({ body, clientAssertion: options.clientAssertion });
        return Promise.resolve({
          body: { credential_id: "cred_123" },
          contentType: "application/aep+json",
          status: 200
        });
      }
    });
    const reply = createReply();

    await handlers.grant(
      {
        body: {
          grant_type: "oauth-bearer"
        },
        headers: {
          authorization: "AEP signed.jwt"
        }
      },
      reply
    );

    expect(calls).toEqual([
      {
        body: {
          grant_type: "oauth-bearer"
        },
        clientAssertion: "signed.jwt"
      }
    ]);
    expect(reply.statusCode).toBe(200);
    expect(reply.body).toEqual({ credential_id: "cred_123" });
  });

  it("handles Inspect and command requests through a real Fastify instance", async () => {
    const calls: Array<{ body: unknown; clientAssertion: string }> = [];
    const app = fastify();

    app.addContentTypeParser(
      "application/aep+json",
      { parseAs: "string" },
      (_request, body, done) => {
        done(null, JSON.parse(body.toString()));
      }
    );
    await createFastifyAepRoutesPlugin({
      ...mockService(),
      enroll: (body, options) => {
        calls.push({ body, clientAssertion: options.clientAssertion });
        return Promise.resolve({
          body: {
            status: "active"
          },
          contentType: "application/aep+json",
          status: 200
        });
      }
    })(app);

    const inspect = await app.inject({
      method: "GET",
      url: "/.well-known/aep"
    });
    expect(inspect.statusCode).toBe(200);
    expect(inspect.headers["content-type"]).toContain("application/aep+json");
    expect(inspect.json()).toMatchObject({
      service: {
        did: "did:web:service.example"
      }
    });

    const enroll = await app.inject({
      headers: {
        authorization: "AEP signed.jwt",
        "content-type": "application/aep+json"
      },
      method: "POST",
      payload: {
        agent_did: "did:web:agent.example.com:agents:123",
        idempotency_key: "idem"
      },
      url: "/aep/enroll"
    });
    expect(enroll.statusCode).toBe(200);
    expect(enroll.headers["content-type"]).toContain("application/aep+json");
    expect(enroll.json()).toEqual({
      status: "active"
    });
    expect(calls).toEqual([
      {
        body: {
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "idem"
        },
        clientAssertion: "signed.jwt"
      }
    ]);

    await app.close();
  });
});

interface CapturedReply extends FastifyAepReply {
  body?: unknown;
  contentType?: string;
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

function createReply(): CapturedReply {
  return {
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
