import { generateKeyPairSync, randomUUID } from "node:crypto";
import { expect, it } from "vitest";
import { signClientAssertionJwt } from "@aep-foundation/core";
import {
  createAepService,
  createJwtClientAssertionVerifier,
  didWebIdentityMethod
} from "@aep-foundation/service";

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const service = createAepService({
    serviceDid: "did:web:api.example.com",
    identityMethods: [didWebIdentityMethod()],
    authenticationMethods: ["aep-jwt"],
    clientAssertionVerifier: createJwtClientAssertionVerifier({ key: publicKey })
  });
  async function authorization(
    resource = "https://api.example.com/orders",
    op: "authenticate" | "enroll" = "authenticate"
  ) {
    const iat = Math.floor(Date.now() / 1000);
    const token = await signClientAssertionJwt(
      {
        iss: "did:web:agent.example",
        sub: "did:web:agent.example",
        aud: "did:web:api.example.com",
        op,
        iat,
        exp: iat + 300,
        jti: randomUUID(),
        ...(op === "authenticate" ? { resource } : {})
      },
      { alg: "EdDSA", key: privateKey }
    );
    return `AEP ${token}`;
  }
  return { service, authorization };
}

import express from "express";
import type { ErrorRequestHandler } from "express";
import { createServer } from "node:http";
import { once } from "node:events";
import {
  createExpressAepProtectedResourceHandler,
  registerExpressAepRoutes
} from "../src/index.js";
import type { AepAuthenticatedPrincipal } from "@aep-foundation/service";
import type { ExpressAepRequest } from "../src/index.js";

async function listen(app: ReturnType<typeof express>) {
  const server = createServer(app);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing server address");
  return {
    base: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      })
  };
}

it("binds a double-slash path and forwards the principal through real Express middleware", async () => {
  const { service, authorization } = fixture();
  const app = express();
  const principals = new WeakMap<ExpressAepRequest, AepAuthenticatedPrincipal>();
  let calls = 0;
  app.use(
    createExpressAepProtectedResourceHandler(
      service,
      "https://api.example.com",
      async (principal, request) => {
        await Promise.resolve();
        calls++;
        principals.set(request, principal);
      }
    )
  );
  app.use((request, response) =>
    response.json({ principal: principals.get(request), payment: request.get("Payment") })
  );
  const server = await listen(app);
  try {
    expect(
      (
        await fetch(server.base + "//other/orders", {
          headers: { authorization: await authorization() }
        })
      ).status
    ).toBe(401);
    const headers = {
      authorization: await authorization("https://api.example.com//other/orders"),
      payment: "payment-value"
    };
    const response = await fetch(server.base + "//other/orders", { headers });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      principal: { agentDid: "did:web:agent.example", authenticationKind: "aep-jwt" },
      payment: "payment-value"
    });
    expect((await fetch(server.base + "//other/orders", { headers })).status).toBe(401);
    expect(calls).toBe(1);
  } finally {
    await server.close();
  }
});

it("stops Express middleware when the principal callback rejects", async () => {
  const { service, authorization } = fixture();
  const app = express();
  let reached = false;
  app.use(
    createExpressAepProtectedResourceHandler(service, "https://api.example.com", async () => {
      await Promise.resolve();
      throw new Error("application authorization denied");
    })
  );
  app.use((_request, response) => {
    reached = true;
    response.json({});
  });
  const onError: ErrorRequestHandler = (_error: unknown, _request, response, _next) => {
    response.sendStatus(403);
  };
  app.use(onError);
  const server = await listen(app);
  try {
    expect(
      (await fetch(server.base + "/orders", { headers: { authorization: await authorization() } }))
        .status
    ).toBe(403);
    expect(reached).toBe(false);
  } finally {
    await server.close();
  }
});

it("parses AEP bodies and isolates malformed-body handling from other Express routes", async () => {
  const { service, authorization } = fixture();
  const app = express();
  const invalidAepJson: ErrorRequestHandler = (error: unknown, request, _response, next) => {
    if (error instanceof SyntaxError && "type" in error && error.type === "entity.parse.failed") {
      request.body = undefined;
      next();
    } else next(error);
  };
  app.use(
    ["/aep/enroll", "/aep/grant", "/aep/revoke"],
    express.json({ type: ["application/json", "application/aep+json"] }),
    invalidAepJson
  );
  registerExpressAepRoutes(app, service);
  app.use(express.json());
  app.post("/ordinary", (request, response) => response.json(request.body));
  const onError: ErrorRequestHandler = (_error: unknown, _request, response, _next) => {
    response.status(400).send("ordinary parser error");
  };
  app.use(onError);
  const server = await listen(app);
  try {
    for (const contentType of ["application/aep+json", "application/json"]) {
      const post = async (body: string, authenticated: boolean) =>
        fetch(server.base + "/aep/enroll", {
          method: "POST",
          body,
          headers: {
            "content-type": contentType,
            "idempotency-key": randomUUID(),
            ...(authenticated ? { authorization: await authorization("", "enroll") } : {})
          }
        });
      expect(
        (await post(JSON.stringify({ agent_did: "did:web:agent.example" }), true)).status
      ).toBe(200);
      const malformed = await post("{", true);
      expect(malformed.status).toBe(400);
      expect(malformed.headers.get("content-type")).toContain("application/problem+json");
      await expect(malformed.json()).resolves.toMatchObject({ code: "invalid_request" });
      expect((await post("{", false)).status).toBe(401);
    }
    const ordinary = await fetch(server.base + "/ordinary", {
      method: "POST",
      body: "{",
      headers: { "content-type": "application/json" }
    });
    expect(ordinary.status).toBe(400);
    await expect(ordinary.text()).resolves.toBe("ordinary parser error");
  } finally {
    await server.close();
  }
});
