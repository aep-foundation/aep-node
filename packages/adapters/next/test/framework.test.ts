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

import { NextRequest } from "next/dist/server/web/spec-extension/request.js";
import { createNextAepProtectedResourceHandler } from "../src/index.js";

it("passes the real principal and original request without consuming the assertion twice", async () => {
  const { service, authorization } = fixture();
  let calls = 0;
  const handler = createNextAepProtectedResourceHandler(service, (request, principal) => {
    calls++;
    return Response.json({ principal, payment: request.headers.get("Payment") });
  });
  const request = new NextRequest("https://api.example.com/orders", {
    headers: { Authorization: await authorization(), Payment: "payment-value" }
  });
  const response = await handler(request);
  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    principal: { agentDid: "did:web:agent.example", authenticationKind: "aep-jwt" },
    payment: "payment-value"
  });
  expect((await handler(request)).status).toBe(401);
  expect((await handler(new NextRequest("https://api.example.com/orders"))).status).toBe(401);
  expect(calls).toBe(1);
});

it("propagates rejection from the authenticated Next application callback", async () => {
  const { service, authorization } = fixture();
  const handler = createNextAepProtectedResourceHandler(service, async () => {
    await Promise.resolve();
    throw new Error("application authorization denied");
  });
  await expect(
    handler(
      new NextRequest("https://api.example.com/orders", {
        headers: { Authorization: await authorization() }
      })
    )
  ).rejects.toThrow("application authorization denied");
});
