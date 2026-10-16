import { describe, expect, it } from "vitest";

import { createHonoAepHandlers, createHonoAepProtectedResourceHandler } from "../src/index.js";
import type { HonoAepContext } from "../src/index.js";
import type {
  AepAuthenticatedServiceOptions,
  AepIdempotentServiceOptions,
  AepService
} from "@aep-foundation/service";

interface CapturedContext extends HonoAepContext {
  body?: unknown;
  headers?: Record<string, string> | undefined;
  statusCode?: number | undefined;
}

interface CapturedCall {
  body?: unknown;
  clientAssertion: string;
  command: string;
  idempotencyKey?: string;
}

interface ContextInput {
  authorization?: string;
  idempotencyKey?: string;
  json?: () => Promise<unknown>;
}

function createContext(input: ContextInput = {}): CapturedContext {
  const fields: Record<string, string | undefined> = {
    Authorization: input.authorization,
    "Idempotency-Key": input.idempotencyKey
  };

  return {
    json(body: unknown, status?: number, headers?: Record<string, string>) {
      this.body = body;
      this.statusCode = status;
      this.headers = headers;
      return new Response(JSON.stringify(body), { status: status ?? 200, headers: headers ?? {} });
    },
    req: {
      header: (name: string) => fields[name],
      json: input.json ?? (() => Promise.resolve({ submitted: true }))
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
  input: ContextInput = {}
): Promise<{ calls: CapturedCall[]; context: CapturedContext }> {
  const calls: CapturedCall[] = [];
  const handlers = createHonoAepHandlers(recordingService(calls));
  const context = createContext(input);

  await handlers[command](context);
  return { calls, context };
}

describe("hono command dispatch", () => {
  it("routes each command to its Service method and echoes the response envelope", async () => {
    for (const command of ["enroll", "grant", "revoke", "status"] as const) {
      const { calls, context } = await runCommand(command, {
        authorization: "AEP header.payload.signature",
        idempotencyKey: "key-1"
      });

      expect(calls).toHaveLength(1);
      expect(calls[0]?.command).toBe(command);
      expect(calls[0]?.clientAssertion).toBe("header.payload.signature");
      expect(context.statusCode).toBe(200);
      expect(context.headers).toEqual({
        "Content-Type": "application/aep+json",
        "X-Adapter": command
      });
      expect(context.body).toEqual({ command });
    }
  });

  it("reads a body for state-mutating commands and none for Status", async () => {
    for (const command of ["enroll", "grant", "revoke"] as const) {
      const { calls } = await runCommand(command, { authorization: "AEP a.b.c" });

      expect(calls[0]?.body).toEqual({ submitted: true });
      expect(calls[0]?.idempotencyKey).toBe("");
    }

    const { calls } = await runCommand("status", { authorization: "AEP a.b.c" });
    expect(calls[0]?.body).toBeUndefined();
    expect(calls[0]?.idempotencyKey).toBeUndefined();
  });

  it("carries the idempotency key on state-mutating commands", async () => {
    const { calls } = await runCommand("grant", {
      authorization: "AEP a.b.c",
      idempotencyKey: "key-1"
    });

    expect(calls[0]?.idempotencyKey).toBe("key-1");
  });
});

describe("hono request body handling", () => {
  it("presents no body when the payload is not JSON, so the Service reports invalid_request", async () => {
    const { calls } = await runCommand("enroll", {
      authorization: "AEP a.b.c",
      json: () => Promise.reject(new SyntaxError("Unexpected token"))
    });

    expect(calls[0]?.body).toBeUndefined();
  });

  it("presents no body when the context exposes no request", async () => {
    const calls: CapturedCall[] = [];
    const handlers = createHonoAepHandlers(recordingService(calls));
    const context: CapturedContext = {
      json(body: unknown, status?: number, headers?: Record<string, string>) {
        this.body = body;
        this.statusCode = status;
        this.headers = headers;
        return new Response(JSON.stringify(body), {
          status: status ?? 200,
          headers: headers ?? {}
        });
      }
    };

    await handlers.enroll(context);

    expect(calls[0]?.body).toBeUndefined();
    expect(calls[0]?.clientAssertion).toBe("");
  });
});

describe("hono Authorization field handling", () => {
  it("accepts a case-insensitive scheme separated by one or more spaces", async () => {
    for (const authorization of [
      "AEP header.payload.signature",
      "aep header.payload.signature",
      "AEP   header.payload.signature",
      "AEP\theader.payload.signature",
      "AEP header.payload.signature  "
    ]) {
      const { calls } = await runCommand("enroll", { authorization });

      expect(calls[0]?.clientAssertion, authorization).toBe("header.payload.signature");
    }
  });

  it("presents no assertion when the field is absent, empty, or not an AEP credential", async () => {
    for (const authorization of [
      undefined,
      "",
      "AEP",
      "Bearer opaque-token",
      "Basic dXNlcjpwYXNz",
      "Payment mpp-credential",
      "AEP a b",
      "AEP first.a.a, AEP second.b.b"
    ]) {
      const { calls } = await runCommand("enroll", {
        ...(authorization === undefined ? {} : { authorization })
      });

      expect(calls[0]?.clientAssertion, String(authorization)).toBe("");
    }
  });
});

describe("hono protected-resource handling", () => {
  it("requires the raw request", async () => {
    const handler = createHonoAepProtectedResourceHandler({
      inspectDocument: () => ({})
    } as never);

    await expect(handler(createContext())).rejects.toThrow("requires req.raw");
  });

  it("returns the Problem Details and challenge headers when authentication fails", async () => {
    const calls: CapturedCall[] = [];
    const handler = createHonoAepProtectedResourceHandler(recordingService(calls));
    const context = createContext();
    context.req = {
      ...context.req,
      header: () => undefined,
      json: () => Promise.resolve({}),
      raw: new Request("https://api.example.com/v1/orders")
    };

    await handler(context);

    expect(context.statusCode).toBe(401);
    expect(context.headers).toEqual({
      "Content-Type": "application/problem+json",
      "WWW-Authenticate": 'AEP service_did="did:web:api.example"'
    });
    expect(context.body).toMatchObject({ code: "authentication_required" });
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
    const handler = createHonoAepProtectedResourceHandler(service);
    const context = createContext();
    context.req = {
      ...context.req,
      header: () => undefined,
      json: () => Promise.resolve({}),
      raw: new Request("https://api.example.com/v1/orders")
    };

    await expect(handler(context)).resolves.toBeUndefined();
  });
});
