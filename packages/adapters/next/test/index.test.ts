import { describe, expect, it } from "vitest";

import { NextRequest } from "next/dist/server/web/spec-extension/request.js";

import { didWebIdentityMethod } from "@aep-foundation/service";

import {
  AEP_NEXT_MEDIA_TYPE,
  createNextAepCommandRouteHandler,
  createNextAepProtectedResourceHandler,
  createNextAepRoute,
  createNextAepRouteHandler,
  packageName
} from "../src/index.js";
import type { AepService } from "@aep-foundation/service";

describe("@aep-foundation/next", () => {
  it("exports the package name", () => {
    expect(packageName).toBe("@aep-foundation/next");
  });

  it("creates a Next route handler", async () => {
    const handler = createNextAepRouteHandler({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });

    const response = await handler();
    const body: unknown = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe(AEP_NEXT_MEDIA_TYPE);
    expect(body).toMatchObject({
      aep_version: "1.0",
      service: {
        did: "did:web:service.example"
      }
    });
  });

  it("exports a GET route object", () => {
    const route = createNextAepRoute({
      identityMethods: [didWebIdentityMethod()],
      serviceDid: "did:web:service.example"
    });

    expect(route.GET).toBeTypeOf("function");
    expect(route.POST).toBeUndefined();
  });

  it("exports command route objects with the expected HTTP methods", () => {
    const statusRoute = createNextAepRoute(mockService(), "status");
    const grantRoute = createNextAepRoute(mockService(), "grant");

    expect(statusRoute.GET).toBeTypeOf("function");
    expect(statusRoute.POST).toBeUndefined();
    expect(grantRoute.GET).toBeUndefined();
    expect(grantRoute.POST).toBeTypeOf("function");
  });

  it("passes command bodies and client assertions to the Service", async () => {
    const calls: Array<{ body: unknown; clientAssertion: string }> = [];
    const handler = createNextAepCommandRouteHandler(
      {
        ...mockService(),
        grant: (body, options) => {
          calls.push({ body, clientAssertion: options.clientAssertion });
          return Promise.resolve({
            body: { credential_id: "cred_123" },
            contentType: "application/aep+json",
            status: 200
          });
        }
      },
      "grant"
    );
    const response = await handler(
      new Request("https://api.example.com/aep/grant", {
        body: JSON.stringify({
          grant_type: "oauth-bearer"
        }),
        headers: {
          Authorization: "AEP signed.jwt",
          "Content-Type": "application/aep+json"
        },
        method: "POST"
      })
    );

    await expect(response.json()).resolves.toEqual({
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

  it("handles command requests created with NextRequest", async () => {
    const calls: Array<{ body: unknown; clientAssertion: string }> = [];
    const route = createNextAepRoute(
      {
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
      },
      "enroll"
    );

    const response = await route.POST?.(
      new NextRequest("https://api.example.com/aep/enroll", {
        body: JSON.stringify({
          agent_did: "did:web:agent.example.com:agents:123",
          idempotency_key: "idem"
        }),
        headers: {
          Authorization: "AEP signed.jwt",
          "Content-Type": "application/aep+json"
        },
        method: "POST"
      })
    );

    expect(response?.status).toBe(200);
    expect(response?.headers.get("content-type")).toBe("application/aep+json");
    await expect(response?.json()).resolves.toEqual({
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
  });

  it("adapts protected-resource failures and authenticated responses", async () => {
    const request = new Request("https://api.example.com/orders");
    const denied = await createNextAepProtectedResourceHandler(mockService(), () =>
      Promise.resolve(new Response("allowed"))
    )(request);
    expect(denied.status).toBe(401);
    await expect(denied.json()).resolves.toMatchObject({ code: "authentication_required" });

    const allowed = createNextAepProtectedResourceHandler(
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
      () => new Response("allowed", { status: 202 })
    );
    expect((await allowed(request)).status).toBe(202);
    await expect(allowed()).rejects.toThrow("request is required");
  });
});

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
