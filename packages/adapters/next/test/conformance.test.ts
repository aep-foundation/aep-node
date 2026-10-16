import { describe, expect, it } from "vitest";

import {
  AEP_NEXT_MEDIA_TYPE,
  createNextAepCommandRouteHandler,
  createNextAepProtectedResourceHandler,
  createNextAepRoute,
  createNextAepRouteHandler
} from "../src/index.js";
import type {
  AepAuthenticatedServiceOptions,
  AepIdempotentServiceOptions,
  AepService
} from "@aep-foundation/service";

interface CapturedCall {
  body?: unknown;
  clientAssertion: string;
  command: string;
  idempotencyKey?: string;
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
    inspectDocument: () => ({ aep_version: "1.0" }) as never,
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

function commandRequest(
  headers: Record<string, string> = {},
  body: string | null = JSON.stringify({ submitted: true })
): Request {
  return new Request("https://api.example.com/aep/enroll", {
    body,
    headers,
    method: "POST"
  });
}

async function runCommand(
  command: "enroll" | "grant" | "revoke" | "status",
  request: Request
): Promise<{ calls: CapturedCall[]; response: Response }> {
  const calls: CapturedCall[] = [];
  const handler = createNextAepCommandRouteHandler(recordingService(calls), command);
  const response = await handler(request);

  return { calls, response };
}

describe("next command dispatch", () => {
  it("routes each command to its Service method and echoes the response envelope", async () => {
    for (const command of ["enroll", "grant", "revoke", "status"] as const) {
      const { calls, response } = await runCommand(
        command,
        commandRequest({
          Authorization: "AEP header.payload.signature",
          "Idempotency-Key": "key-1"
        })
      );

      expect(calls).toHaveLength(1);
      expect(calls[0]?.command).toBe(command);
      expect(calls[0]?.clientAssertion).toBe("header.payload.signature");
      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("application/aep+json");
      expect(response.headers.get("X-Adapter")).toBe(command);
      await expect(response.json()).resolves.toEqual({ command });
    }
  });

  it("reads a body for state-mutating commands and none for Status", async () => {
    for (const command of ["enroll", "grant", "revoke"] as const) {
      const { calls } = await runCommand(
        command,
        commandRequest({ Authorization: "AEP a.b.c", "Idempotency-Key": "key-1" })
      );

      expect(calls[0]?.body).toEqual({ submitted: true });
      expect(calls[0]?.idempotencyKey).toBe("key-1");
    }

    const { calls } = await runCommand(
      "status",
      commandRequest({ Authorization: "AEP a.b.c", "Idempotency-Key": "key-1" })
    );
    expect(calls[0]?.body).toBeUndefined();
    expect(calls[0]?.idempotencyKey).toBeUndefined();
  });

  it("requires a request", async () => {
    const handler = createNextAepCommandRouteHandler(
      { inspectDocument: () => ({}) } as never,
      "enroll"
    );

    await expect(handler()).rejects.toThrow("An AEP command request is required.");
  });
});

describe("next request body handling", () => {
  it("presents no body when the payload is not JSON, so the Service reports invalid_request", async () => {
    const { calls } = await runCommand(
      "enroll",
      commandRequest({ Authorization: "AEP a.b.c" }, "{not json")
    );

    expect(calls[0]?.body).toBeUndefined();
  });

  it("presents no body when the request carries none", async () => {
    const { calls } = await runCommand(
      "enroll",
      commandRequest({ Authorization: "AEP a.b.c" }, null)
    );

    expect(calls[0]?.body).toBeUndefined();
  });
});

describe("next Authorization field handling", () => {
  it("accepts a case-insensitive scheme separated by one or more spaces", async () => {
    for (const authorization of [
      "AEP header.payload.signature",
      "aep header.payload.signature",
      "AEP   header.payload.signature",
      "AEP\theader.payload.signature"
    ]) {
      const { calls } = await runCommand(
        "enroll",
        commandRequest({ Authorization: authorization })
      );

      expect(calls[0]?.clientAssertion, authorization).toBe("header.payload.signature");
    }
  });

  it("presents no assertion when the field is absent or not an AEP credential", async () => {
    for (const authorization of [
      undefined,
      "AEP",
      "Bearer opaque-token",
      "Basic dXNlcjpwYXNz",
      "Payment mpp-credential",
      "AEP a b"
    ]) {
      const { calls } = await runCommand(
        "enroll",
        commandRequest(authorization === undefined ? {} : { Authorization: authorization })
      );

      expect(calls[0]?.clientAssertion, String(authorization)).toBe("");
    }
  });

  it("presents no assertion when duplicate field lines were joined", async () => {
    const headers = new Headers();
    headers.append("Authorization", "AEP first.a.a");
    headers.append("Authorization", "AEP second.b.b");
    const request = new Request("https://api.example.com/aep/enroll", {
      body: JSON.stringify({}),
      headers,
      method: "POST"
    });

    const { calls } = await runCommand("enroll", request);

    expect(calls[0]?.clientAssertion).toBe("");
  });
});

describe("next Inspect route handler", () => {
  it("serves the Inspect document as AEP JSON", async () => {
    const handler = createNextAepRouteHandler(recordingService([]));
    const response = await handler();

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe(AEP_NEXT_MEDIA_TYPE);
    await expect(response.json()).resolves.toEqual({ aep_version: "1.0" });
  });
});

describe("next route method mapping", () => {
  it("binds Inspect and Status to GET and the mutating commands to POST", () => {
    const service = recordingService([]);

    expect(Object.keys(createNextAepRoute(service))).toEqual(["GET"]);
    expect(Object.keys(createNextAepRoute(service, "inspect"))).toEqual(["GET"]);
    expect(Object.keys(createNextAepRoute(service, "status"))).toEqual(["GET"]);

    for (const command of ["enroll", "grant", "revoke"] as const) {
      expect(Object.keys(createNextAepRoute(service, command))).toEqual(["POST"]);
    }
  });

  it("dispatches through the mapped handler", async () => {
    const calls: CapturedCall[] = [];
    const route = createNextAepRoute(recordingService(calls), "revoke");
    const response = await route.POST?.(
      commandRequest({ Authorization: "AEP a.b.c", "Idempotency-Key": "key-1" })
    );

    expect(response?.status).toBe(200);
    expect(calls[0]?.command).toBe("revoke");
  });
});

describe("next protected-resource handling", () => {
  it("requires a request", async () => {
    const handler = createNextAepProtectedResourceHandler(
      { inspectDocument: () => ({}) } as never,
      () => new Response(null, { status: 204 })
    );

    await expect(handler()).rejects.toThrow("A protected-resource request is required.");
  });

  it("returns the Problem Details and challenge headers when authentication fails", async () => {
    const handler = createNextAepProtectedResourceHandler(
      recordingService([]),
      () => new Response(null, { status: 204 })
    );
    const response = await handler(new Request("https://api.example.com/v1/orders"));

    expect(response.status).toBe(401);
    expect(response.headers.get("Content-Type")).toBe("application/problem+json");
    expect(response.headers.get("WWW-Authenticate")).toBe('AEP service_did="did:web:api.example"');
    await expect(response.json()).resolves.toMatchObject({ code: "authentication_required" });
  });

  it("hands an authenticated request to the wrapped route handler", async () => {
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
    let seen: string | undefined;
    const handler = createNextAepProtectedResourceHandler(service, (request) => {
      seen = request.url;
      return new Response(null, { status: 204 });
    });

    const response = await handler(new Request("https://api.example.com/v1/orders"));

    expect(response.status).toBe(204);
    expect(seen).toBe("https://api.example.com/v1/orders");
  });
});
