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

const adapterName = "express";
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
    logExampleServiceInteraction(adapterName, request.method, request.path, response.statusCode);
  });
  next();
});
registerExpressAepRoutes(app, service);
app.get("/api/resource", requireAepJwt, (_request, response) => {
  response.json(resourceBody());
});
app.post("/api/profile", requireAepJwt, (request, response) => {
  response.json(profileBody(requestBody(request)));
});

app.listen(port, host, () => {
  console.log(`AEP ${adapterName} service listening on ${listenUrl}`);
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
