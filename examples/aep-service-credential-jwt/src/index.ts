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
  exampleServicePorts,
  logExampleServiceInteraction,
  requiredExampleConfig
} from "../../_shared/aep-examples.js";

const serviceName = "jwt";
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
app.get("/api/resource", requireAepJwt, (_request, response) => {
  response.json({
    message: "This resource was returned after AEP JWT authentication.",
    resource: "example-resource"
  });
});
app.post("/api/profile", requireAepJwt, (request, response) => {
  response.json({
    profile: requestBody(request),
    updated: true
  });
});

app.listen(port, host, () => {
  console.log(`AEP JWT service listening on ${listenUrl}`);
  console.log(`Service DID: ${serviceDid}`);
});

async function authenticateProtectedRoute(request: Request, response: Response): Promise<boolean> {
  const status = await authenticateProtectedResource(service, request.header("authorization"));

  if (status.status !== 200 || !isActiveProtectedResourceAuthentication(status)) {
    response.type(status.contentType).status(status.status).json(status.body);
    return false;
  }

  return true;
}

function requestBody(request: Request): unknown {
  return request.body as unknown;
}

function parsePort(value: string): number {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    throw new TypeError(`Invalid PORT: ${value}`);
  }

  return parsed;
}
