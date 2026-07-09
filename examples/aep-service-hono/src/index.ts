import { createServer } from "node:http";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { registerHonoAepRoutes } from "@aep-foundation/hono";
import {
  authenticateProtectedResource,
  createAepService,
  createDidWebClientAssertionVerifier,
  didWebIdentityMethod,
  isActiveProtectedResourceAuthentication
} from "@aep-foundation/service";
import { Hono } from "hono";

import {
  exampleListenUrl,
  exampleServicePorts,
  logExampleServiceInteraction,
  requiredExampleConfig
} from "../../_shared/aep-examples.js";

const adapterName = "hono";
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
const app = new Hono();

registerHonoAepRoutes(app, service);
app.get("/api/resource", async (context) => {
  const denied = await deniedProtectedResponse(context.req.header("Authorization"));

  if (denied !== undefined) {
    return denied;
  }

  return context.json(resourceBody());
});
app.post("/api/profile", async (context) => {
  const denied = await deniedProtectedResponse(context.req.header("Authorization"));

  if (denied !== undefined) {
    return denied;
  }

  return context.json(profileBody(await context.req.json()));
});

const server = createServer((request, response) => {
  void handleNodeRequest(request, response).catch((error: unknown) => {
    json(response, 500, {
      error: "internal_error",
      message: error instanceof Error ? error.message : "Unknown error"
    });
  });
});

server.listen(port, host, () => {
  console.log(`AEP ${adapterName} service listening on ${listenUrl}`);
  console.log(`Service DID: ${serviceDid}`);
});

async function handleNodeRequest(
  request: IncomingMessage,
  response: ServerResponse
): Promise<void> {
  const webResponse = await app.fetch(await toWebRequest(request));
  const body = Buffer.from(await webResponse.arrayBuffer());

  webResponse.headers.forEach((value, key) => response.setHeader(key, value));
  response.writeHead(webResponse.status);
  response.end(body);
  logExampleServiceInteraction(adapterName, request.method, request.url, webResponse.status);
}

async function deniedProtectedResponse(
  authorization: string | undefined
): Promise<Response | undefined> {
  const status = await authenticateProtectedResource(service, authorization);

  if (status.status === 200 && isActiveProtectedResourceAuthentication(status)) {
    return undefined;
  }

  return new Response(JSON.stringify(status.body), {
    headers: {
      "content-type": status.contentType
    },
    status: status.status
  });
}

async function toWebRequest(request: IncomingMessage): Promise<Request> {
  const method = request.method ?? "GET";
  const init: RequestInit = {
    headers: headersFromNode(request.headers),
    method
  };
  const body = method === "GET" || method === "HEAD" ? undefined : await readRequestBody(request);

  return new Request(`http://${request.headers.host ?? `${host}:${port}`}${request.url ?? "/"}`, {
    ...init,
    ...(body === undefined || body.length === 0 ? {} : { body })
  });
}

function headersFromNode(headers: IncomingHttpHeaders): Headers {
  const result = new Headers();

  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }

    if (Array.isArray(value)) {
      value.forEach((item) => result.append(key, item));
      continue;
    }

    result.set(key, value);
  }

  return result;
}

function readRequestBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];

    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("error", reject);
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
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

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body, null, 2));
}
