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

import { Hono } from "hono";
import { createHonoAepProtectedResourceHandler } from "../src/index.js";
import type { AepAuthenticatedPrincipal } from "@aep-foundation/service";
import type { HonoAepContext } from "../src/index.js";

it("authenticates once, passes the principal, and continues real Hono middleware", async () => {
  const { service, authorization } = fixture();
  const principals = new WeakMap<HonoAepContext, AepAuthenticatedPrincipal>();
  let calls = 0;
  const app = new Hono();
  app.use(
    "/orders",
    createHonoAepProtectedResourceHandler(service, async (principal, context) => {
      await Promise.resolve();
      calls++;
      principals.set(context, principal);
    })
  );
  app.get("/orders", (context) =>
    context.json({
      principal: principals.get(context),
      payment: context.req.header("Payment")
    })
  );
  const headers = { Authorization: await authorization(), Payment: "payment-value" };
  const response = await app.request("https://api.example.com/orders", { headers });
  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    principal: { agentDid: "did:web:agent.example", authenticationKind: "aep-jwt" },
    payment: "payment-value"
  });
  expect(calls).toBe(1);
  expect((await app.request("https://api.example.com/orders", { headers })).status).toBe(401);
  expect((await app.request("https://api.example.com/orders")).status).toBe(401);
  expect(calls).toBe(1);
});

it("does not continue Hono middleware when the principal callback rejects", async () => {
  const { service, authorization } = fixture();
  const app = new Hono();
  let reached = false;
  app.onError(() => new Response("denied", { status: 403 }));
  app.use(
    "/orders",
    createHonoAepProtectedResourceHandler(service, async () => {
      await Promise.resolve();
      throw new Error("application authorization denied");
    })
  );
  app.get("/orders", (context) => {
    reached = true;
    return context.text("allowed");
  });
  expect(
    (
      await app.request("https://api.example.com/orders", {
        headers: { Authorization: await authorization() }
      })
    ).status
  ).toBe(403);
  expect(reached).toBe(false);
});
