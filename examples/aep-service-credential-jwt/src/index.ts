import { registerExpressAepRoutes } from "@aep-foundation/express";
import {
  authenticateProtectedResource,
  createAepService,
  createDidWebClientAssertionVerifier,
  didWebIdentityMethod,
  isActiveProtectedResourceAuthentication
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
  logExampleServiceUrls,
  logExampleServiceInteraction,
  requiredExampleConfig
} from "../../_shared/aep-examples.js";

const serviceName = "jwt";
const host = process.env["HOST"] ?? "127.0.0.1";
const port = parsePort(process.env["PORT"] ?? "3000");
const listenUrl = exampleListenUrl(host, port);
const serviceDid = requiredExampleConfig("SERVICE_DID", process.env["SERVICE_DID"]);

const service = createAepService({
  authenticationMethods: ["aep-jwt"],
  ...exampleOpenApiAdvertisement(),
  ...exampleServicePorts(),
  clientAssertionVerifier: createDidWebClientAssertionVerifier({ allowInsecureLoopback: true }),
  identityMethods: [didWebIdentityMethod()],
  serviceDid
});

const requireAepJwt: RequestHandler = (request, response, next) => {
  void authenticateProtectedRoute(request, response)
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
    logExampleServiceInteraction(serviceName, request.method, request.path, response.statusCode);
  });
  next();
});
registerExpressAepRoutes(app, service);
app.get(exampleServiceDidPath(serviceDid), (_request, response) =>
  response.json(exampleServiceDidDocument(serviceDid))
);
app.get("/openapi.json", (_request, response) => response.json(exampleOpenApi("aep-jwt")));
app.get("/api/resource", requireAepJwt, (_request, response) => {
  response.json({
    widgets: [1, 2, 3]
  });
});
app.post("/api/profile", requireAepJwt, (_request, response) => {
  response.json({
    status: "received"
  });
});

app.listen(port, host, () => {
  logExampleServiceUrls(`${serviceName} credential`, listenUrl, serviceDid);
});

async function authenticateProtectedRoute(request: Request, response: Response): Promise<boolean> {
  const status = await authenticateProtectedResource(service, {
    headers: request.headers,
    method: request.method,
    url: new URL(request.originalUrl, listenUrl)
  });

  if (!isActiveProtectedResourceAuthentication(status)) {
    for (const [name, value] of Object.entries(status.response.headers ?? {}))
      response.set(name, value);
    response
      .type(status.response.contentType)
      .status(status.response.status)
      .json(status.response.body);
    return false;
  }

  return true;
}

function parsePort(value: string): number {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    throw new TypeError(`Invalid PORT: ${value}`);
  }

  return parsed;
}
