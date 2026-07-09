import { randomUUID } from "node:crypto";

import {
  createAepAgent,
  createPlatformIdentityProvider,
  discoverPlatform
} from "@aep-foundation/agent";

const platformUrl = process.env["PLATFORM_URL"] ?? "http://127.0.0.1:4100";
const serviceUrl = process.env["SERVICE_URL"] ?? "http://127.0.0.1:3000";
const platformAuthorization = process.env["PLATFORM_AUTHORIZATION"] ?? "Bearer demo-agent";

const agent = createAepAgent({
  identityProvider: createPlatformIdentityProvider({
    authorization: platformAuthorization,
    idempotencyKey: randomUUID(),
    platformUrl
  })
});
const session = agent.serviceSession({ serviceUrl });
const platform = await discoverPlatform({ platformUrl });
const inspect = await session.inspect();
const identity = await session.identity();

console.log(
  JSON.stringify(
    {
      agentDid: identity.agentDid,
      commands: inspect.document.commands.supported,
      grantTypes: inspect.document.commands.grant_types ?? [],
      platformDid: platform.document.platform.did,
      serviceDid: inspect.document.service.did,
      serviceUrl
    },
    null,
    2
  )
);
