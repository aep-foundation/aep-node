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
  exampleServiceDidDocument,
  exampleServiceDidPath,
  exampleServicePorts,
  logExampleServiceUrls,
  logExampleServiceInteraction,
  requiredExampleConfig
} from "../../_shared/aep-examples.js";

const adapterName = "fastify";
const host = process.env["HOST"] ?? "127.0.0.1";
const port = parsePort(process.env["PORT"] ?? "3000");
const listenUrl = exampleListenUrl(host, port);
const serviceDid = requiredExampleConfig("SERVICE_DID", process.env["SERVICE_DID"]);

const service = createAepService({
  authenticationMethods: ["aep-jwt"],
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
app.get(exampleServiceDidPath(serviceDid), () => exampleServiceDidDocument(serviceDid));
app.get("/api/resource", { preHandler: requireAepJwt }, () => resourceBody());
app.post("/api/profile", { preHandler: requireAepJwt }, () => profileBody());

await app.listen({ host, port });
logExampleServiceUrls(adapterName, listenUrl, serviceDid);

async function requireAepJwt(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const status = await authenticateProtectedResource(service, {
    headers: request.headers,
    method: request.method,
    url: new URL(request.url, listenUrl)
  });

  if (!isActiveProtectedResourceAuthentication(status)) {
    for (const [name, value] of Object.entries(status.response.headers ?? {}))
      reply.header(name, value);
    reply
      .type(status.response.contentType)
      .status(status.response.status)
      .send(status.response.body);
  }
}

function resourceBody(): Record<string, unknown> {
  return {
    widgets: [1, 2, 3]
  };
}

function profileBody(): Record<string, unknown> {
  return {
    status: "received"
  };
}

function parsePort(value: string): number {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    throw new TypeError(`Invalid PORT: ${value}`);
  }

  return parsed;
}
