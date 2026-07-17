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
  logExampleServiceUrls,
  logExampleServiceInteraction,
  requiredExampleConfig
} from "../../_shared/aep-examples.js";

const adapterName = "express";
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
  response.json(profileBody());
});

app.listen(port, host, () => {
  logExampleServiceUrls(adapterName, listenUrl, serviceDid);
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
