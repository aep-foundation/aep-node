import { randomUUID } from "node:crypto";

import { AEP_GRANT_TYPE_BASIC } from "@aep-foundation/core";
import type { BasicGrantResponse } from "@aep-foundation/core";
import { registerExpressAepRoutes } from "@aep-foundation/express";
import {
  createAepService,
  createDidWebClientAssertionVerifier,
  createInMemoryServiceCredentialStore,
  didWebIdentityMethod,
  storedBasicGrantType
} from "@aep-foundation/service";
import express from "express";
import type { Request, RequestHandler, Response } from "express";

import {
  exampleListenUrl,
  exampleOpenApi,
  exampleOpenApiAdvertisement,
  exampleServiceDidDocument,
  exampleServiceDidPath,
  exampleServicePorts,
  logExampleCredentialIssued,
  logExampleServiceInteraction,
  logExampleServiceUrls,
  parsePort,
  profileBody,
  requiredExampleConfig,
  resourceBody
} from "../../_shared/aep-examples.js";

const adapterName = "basic";
const host = process.env["HOST"] ?? "127.0.0.1";
const port = parsePort(process.env["PORT"] ?? "3000");
const listenUrl = exampleListenUrl(host, port);
const serviceDid = requiredExampleConfig("SERVICE_DID", process.env["SERVICE_DID"]);
const credentialStore = createInMemoryServiceCredentialStore();

const service = createAepService({
  ...exampleOpenApiAdvertisement(),
  ...exampleServicePorts(),
  authenticationMethods: [AEP_GRANT_TYPE_BASIC],
  clientAssertionVerifier: createDidWebClientAssertionVerifier({ allowInsecureLoopback: true }),
  grantTypes: [
    storedBasicGrantType({
      issue: (_request, context): BasicGrantResponse => {
        const credential: BasicGrantResponse = {
          credential_id: randomUUID(),
          expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          password: randomUUID(),
          realm: "AEP Example",
          scopes: ["read:resource", "write:profile"],
          username: randomUUID()
        };

        logExampleCredentialIssued(
          adapterName,
          AEP_GRANT_TYPE_BASIC,
          context.agentDid,
          credential.credential_id
        );
        return credential;
      },
      store: credentialStore
    })
  ],
  identityMethods: [didWebIdentityMethod()],
  serviceDid
});

const requireCredential: RequestHandler = (request, response, next) => {
  void authenticateCredential(request, response)
    .then((authenticated) => {
      if (authenticated) {
        next();
      }
    })
    .catch(next);
};

const app = express();
app.use(express.json({ type: ["application/json", "application/aep+json"] }));
app.use((request, response, next) => {
  response.on("finish", () => {
    logExampleServiceInteraction(adapterName, request.method, request.path, response.statusCode);
  });
  next();
});
registerExpressAepRoutes(app, service);
app.get(exampleServiceDidPath(serviceDid), (_request, response) =>
  response.json(exampleServiceDidDocument(serviceDid))
);
app.get("/openapi.json", (_request, response) => response.json(exampleOpenApi("basic")));
app.get("/api/resource", requireCredential, (_request, response) => {
  response.json(resourceBody());
});
app.post("/api/profile", requireCredential, (_request, response) => {
  response.json(profileBody());
});

app.listen(port, host, () => {
  logExampleServiceUrls(`${adapterName} credential`, listenUrl, serviceDid);
});

async function authenticateCredential(request: Request, response: Response): Promise<boolean> {
  const result = await service.authenticateProtectedResource({
    headers: request.headers,
    method: request.method,
    url: new URL(request.originalUrl, listenUrl)
  });
  if (result.authenticated) return true;
  for (const [name, value] of Object.entries(result.response.headers ?? {}))
    response.set(name, value);
  response
    .type(result.response.contentType)
    .status(result.response.status)
    .json(result.response.body);
  return false;
}
