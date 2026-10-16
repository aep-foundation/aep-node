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

import fastify from "fastify";
import {
  createFastifyAepProtectedResourceHandler,
  createFastifyAepRoutesPlugin
} from "../src/index.js";
import type { AepAuthenticatedPrincipal } from "@aep-foundation/service";
import type { FastifyAepRequest } from "../src/index.js";

it("binds a double-slash path and forwards the principal through real Fastify hooks", async () => {
  const { service, authorization } = fixture();
  const app = fastify();
  const principals = new WeakMap<FastifyAepRequest, AepAuthenticatedPrincipal>();
  let calls = 0;
  app.get(
    "//other/orders",
    {
      preHandler: createFastifyAepProtectedResourceHandler(
        service,
        "https://api.example.com",
        async (principal, request) => {
          await Promise.resolve();
          calls++;
          principals.set(request, principal);
        }
      )
    },
    (request) => ({ principal: principals.get(request), payment: request.headers["payment"] })
  );
  try {
    expect(
      (
        await app.inject({
          url: "//other/orders",
          headers: { authorization: await authorization() }
        })
      ).statusCode
    ).toBe(401);
    const headers = {
      authorization: await authorization("https://api.example.com//other/orders"),
      payment: "payment-value"
    };
    const response = await app.inject({ url: "//other/orders", headers });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      principal: { agentDid: "did:web:agent.example", authenticationKind: "aep-jwt" },
      payment: "payment-value"
    });
    expect((await app.inject({ url: "//other/orders", headers })).statusCode).toBe(401);
    expect(calls).toBe(1);
  } finally {
    await app.close();
  }
});

it("stops the Fastify route when the principal callback rejects", async () => {
  const { service, authorization } = fixture();
  const app = fastify();
  let reached = false;
  app.get(
    "/orders",
    {
      preHandler: createFastifyAepProtectedResourceHandler(
        service,
        "https://api.example.com",
        async () => {
          await Promise.resolve();
          throw new Error("application authorization denied");
        }
      )
    },
    () => {
      reached = true;
      return {};
    }
  );
  try {
    expect(
      (await app.inject({ url: "/orders", headers: { authorization: await authorization() } }))
        .statusCode
    ).toBe(500);
    expect(reached).toBe(false);
  } finally {
    await app.close();
  }
});

it("parses AEP bodies and isolates malformed-body handling from other Fastify routes", async () => {
  const { service, authorization } = fixture();
  const app = fastify();
  await app.register(async (aep) => {
    const parseJson = aep.getDefaultJsonParser("error", "error");
    aep.removeContentTypeParser("application/json");
    aep.addContentTypeParser<string>(
      ["application/json", "application/aep+json"],
      { parseAs: "string" },
      (request, body, done) => {
        return parseJson(request, body, (error, value) => done(null, error ? undefined : value));
      }
    );
    await aep.register(createFastifyAepRoutesPlugin(service));
  });
  app.post("/ordinary", (request) => request.body);
  try {
    for (const contentType of ["application/aep+json", "application/json"]) {
      const post = async (payload: string, authenticated: boolean) =>
        app.inject({
          method: "POST",
          url: "/aep/enroll",
          payload,
          headers: {
            "content-type": contentType,
            "idempotency-key": randomUUID(),
            ...(authenticated ? { authorization: await authorization("", "enroll") } : {})
          }
        });
      const valid = await post(JSON.stringify({ agent_did: "did:web:agent.example" }), true);
      expect(valid.statusCode).toBe(200);
      const malformed = await post("{", true);
      expect(malformed.statusCode).toBe(400);
      expect(malformed.headers["content-type"]).toContain("application/problem+json");
      expect(malformed.json()).toMatchObject({ code: "invalid_request" });
      expect((await post("{", false)).statusCode).toBe(401);
    }
    const ordinary = await app.inject({
      method: "POST",
      url: "/ordinary",
      payload: "{",
      headers: { "content-type": "application/json" }
    });
    expect(ordinary.statusCode).toBe(400);
    expect(ordinary.headers["content-type"]).toContain("application/json");
    expect(ordinary.json()).not.toHaveProperty("type");
  } finally {
    await app.close();
  }
});
