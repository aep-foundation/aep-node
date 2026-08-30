import { randomUUID } from "node:crypto";

import { createAepAgent, createPlatformIdentityProvider } from "@aep-foundation/agent";
import { parseBuiltInGrantResponse } from "@aep-foundation/core";
import type {
  AepBuiltInGrantType,
  AepProtectedResourceAuthorizationCarrier
} from "@aep-foundation/core";

import { isBuiltInGrantType } from "../../_shared/aep-examples.js";

const platformUrl = process.env["PLATFORM_URL"] ?? "http://127.0.0.1:4100";
const serviceUrl = process.env["SERVICE_URL"] ?? "http://127.0.0.1:3000";
const platformAuthorization = process.env["PLATFORM_AUTHORIZATION"] ?? "Bearer demo-agent";
const protectedResourceCarrier: AepProtectedResourceAuthorizationCarrier =
  process.env["AEP_AUTHORIZATION_CARRIER"] === "dedicated" ? "dedicated" : "standard";

const agent = createAepAgent({
  allowInsecureLoopback: true,
  assertionJti: randomUUID,
  identityProvider: createPlatformIdentityProvider({
    authorization: platformAuthorization,
    idempotencyKey: randomUUID(),
    platformUrl
  })
});
const session = agent.serviceSession({ serviceUrl });
const inspect = await session.inspect();
const identity = await session.identity();
const enroll = await session.enroll({
  idempotencyKey: randomUUID()
});
const statusBeforeGrant = await session.status();
const grantType = advertisedBuiltInGrantType();
const grant =
  grantType === undefined
    ? undefined
    : await session.grant({
        grantType,
        idempotencyKey: randomUUID(),
        requestedScopes: ["read:resource", "write:profile"]
      });
const credential =
  grantType === undefined || grant === undefined
    ? undefined
    : parseBuiltInGrantResponse(grantType, grant.body);
const protectedHeaders = (url: URL): Promise<Record<string, string>> =>
  credential === undefined || grantType === undefined
    ? session.authenticationHeaders({
        carrier: protectedResourceCarrier,
        preferCredential: false,
        resource: String(url)
      })
    : session.authenticationHeaders({
        carrier: protectedResourceCarrier,
        credentialId: credential.credential_id,
        grantType,
        resource: String(url)
      });
const resource = await fetchProtectedJson(
  new URL("/api/resource", serviceUrl),
  {},
  protectedHeaders
);
const profile = await fetchProtectedJson(
  new URL("/api/profile", serviceUrl),
  {
    body: JSON.stringify({
      displayName: "Example Agent"
    }),
    headers: {
      "content-type": "application/json"
    },
    method: "POST"
  },
  protectedHeaders
);
const revoke =
  credential === undefined || grantType === undefined
    ? undefined
    : await session.revoke({
        credentialId: credential.credential_id,
        grantType,
        idempotencyKey: randomUUID()
      });
const statusAfterRevoke = await session.status();

console.log(
  JSON.stringify(
    {
      agentDid: identity.agentDid,
      credentialMode: grantType ?? "jwt",
      enroll: enroll.body,
      grant: grant?.body ?? null,
      profile,
      resource,
      revoke: revoke?.body ?? null,
      serviceDid: inspect.document.service.did,
      statusAfterRevoke: statusAfterRevoke.body,
      statusBeforeGrant: statusBeforeGrant.body
    },
    null,
    2
  )
);

async function fetchProtectedJson(
  url: URL,
  init: RequestInit = {},
  authenticationHeaders: (url: URL) => Promise<Record<string, string>>
): Promise<unknown> {
  const headers = new Headers(init.headers);

  for (const [name, value] of Object.entries(await authenticationHeaders(url))) {
    headers.set(name, value);
  }

  const response = await fetch(url, {
    ...init,
    headers
  });

  if (!response.ok) {
    throw new Error(`Protected request failed: ${response.status}`);
  }

  return response.json();
}

function advertisedBuiltInGrantType(): AepBuiltInGrantType | undefined {
  return inspect.document.commands.grant_types?.find(isBuiltInGrantType);
}
