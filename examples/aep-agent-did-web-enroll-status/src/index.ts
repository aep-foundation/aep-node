import { randomUUID } from "node:crypto";

import { createAepAgent, createPlatformIdentityProvider } from "@aep-foundation/agent";
import {
  AEP_CLAIM_NAME_CONTACT_EMAIL,
  AEP_CLAIM_NAME_PERSON_USERNAME,
  evaluateAepClaimSupport
} from "@aep-foundation/core";
import type {
  AepBuiltInGrantType,
  AepClaimName,
  AepClaimValues,
  AepInspectClaims
} from "@aep-foundation/core";

import { isBuiltInGrantType } from "../../_shared/aep-examples.js";

const platformUrl = process.env["PLATFORM_URL"] ?? "http://127.0.0.1:4100";
const serviceUrl = process.env["SERVICE_URL"] ?? "http://127.0.0.1:3000";
const platformAuthorization = process.env["PLATFORM_AUTHORIZATION"] ?? "Bearer demo-agent";

const agent = createAepAgent({
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
const availableClaims: AepClaimValues = {
  [AEP_CLAIM_NAME_CONTACT_EMAIL]: "example-agent@example.com",
  [AEP_CLAIM_NAME_PERSON_USERNAME]: "example-agent"
};
const claims = claimsForEnrollment(inspect.document.claims, availableClaims);
const enroll = await session.enroll({
  ...(Object.keys(claims).length === 0 ? {} : { claims }),
  idempotencyKey: randomUUID()
});
const status = await session.status();
const grantType = advertisedBuiltInGrantType();
const grant =
  grantType === undefined
    ? undefined
    : await session.grant({
        grantType,
        idempotencyKey: randomUUID(),
        requestedScopes: ["read:resource", "write:profile"]
      });
const protectedHeaders = (url: URL): Promise<Record<string, string>> =>
  session.authenticationHeaders({
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

console.log(
  JSON.stringify(
    {
      agentDid: identity.agentDid,
      credentialMode: grantType ?? "jwt",
      enroll: enroll.body,
      grant: grant?.body,
      profile,
      resource,
      serviceDid: inspect.document.service.did,
      submittedClaimNames: Object.keys(claims).sort(),
      status: status.body
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

function claimsForEnrollment(
  requested: AepInspectClaims | undefined,
  available: AepClaimValues
): AepClaimValues {
  const support = evaluateAepClaimSupport(requested, Object.keys(available));

  if (!support.canSatisfyRequired) {
    throw new Error(
      `Example Agent cannot satisfy required AEP Claim Names: ${support.unsupportedRequired.join(
        ", "
      )}.`
    );
  }

  const selectedClaimNames = new Set<AepClaimName>([
    ...(requested?.required ?? []),
    ...support.supportedPreferred
  ]);
  const submitted = structuredClone(available);

  for (const claimName of Object.keys(submitted)) {
    if (!selectedClaimNames.has(claimName)) {
      delete submitted[claimName];
    }
  }

  return submitted;
}
