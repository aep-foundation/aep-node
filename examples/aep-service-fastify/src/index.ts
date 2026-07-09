import { createFastifyAepRoutesPlugin } from "@aep-foundation/fastify";
import {
  authenticateProtectedResource,
  createAepService,
  createDidWebClientAssertionVerifier,
  didWebIdentityMethod,
  isActiveProtectedResourceAuthentication
} from "@aep-foundation/service";
import fastify from "fastify";
import type { FastifyReply, FastifyRequest } from "fastify";

import {
  exampleListenUrl,
  exampleServicePorts,
  logExampleServiceInteraction,
  requiredExampleConfig
} from "../../_shared/aep-examples.js";

const adapterName = "fastify";
const host = process.env["HOST"] ?? "127.0.0.1";
const port = parsePort(process.env["PORT"] ?? "3000");
const listenUrl = exampleListenUrl(host, port);
const serviceDid = requiredExampleConfig("SERVICE_DID", process.env["SERVICE_DID"]);

const service = createAepService({
  ...exampleServicePorts(),
  clientAssertionVerifier: createDidWebClientAssertionVerifier(),
  identityMethods: [didWebIdentityMethod()],
  serviceDid
});
const app = fastify({ logger: false });

app.addHook("onResponse", (request, reply, done) => {
  logExampleServiceInteraction(adapterName, request.method, request.url, reply.statusCode);
  done();
});
app.addContentTypeParser("application/aep+json", { parseAs: "string" }, (_request, body, done) => {
  try {
    done(null, JSON.parse(typeof body === "string" ? body : body.toString("utf8")));
  } catch (error) {
    done(error instanceof Error ? error : new Error("Invalid AEP JSON request body."));
  }
});
await app.register(createFastifyAepRoutesPlugin(service));
app.get("/api/resource", { preHandler: requireAepJwt }, () => resourceBody());
app.post("/api/profile", { preHandler: requireAepJwt }, (request) => profileBody(request.body));

await app.listen({ host, port });
console.log(`AEP ${adapterName} service listening on ${listenUrl}`);
console.log(`Service DID: ${serviceDid}`);

async function requireAepJwt(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const status = await authenticateProtectedResource(service, request.headers.authorization);

  if (status.status !== 200 || !isActiveProtectedResourceAuthentication(status)) {
    reply.type(status.contentType).status(status.status).send(status.body);
  }
}

function resourceBody(): Record<string, unknown> {
  return {
    adapter: adapterName,
    message: "This resource was returned after AEP JWT authentication.",
    resource: "example-resource"
  };
}

function profileBody(profile: unknown): Record<string, unknown> {
  return {
    adapter: adapterName,
    profile,
    updated: true
  };
}

function parsePort(value: string): number {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    throw new TypeError(`Invalid PORT: ${value}`);
  }

  return parsed;
}
