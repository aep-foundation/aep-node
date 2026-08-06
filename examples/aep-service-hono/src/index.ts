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
  exampleServiceDidDocument,
  exampleServiceDidPath,
  exampleServicePorts,
  logExampleServiceUrls,
  logExampleServiceInteraction,
  requiredExampleConfig
} from "../../_shared/aep-examples.js";

const adapterName = "hono";
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
const app = new Hono();

registerHonoAepRoutes(app, service);
app.get(exampleServiceDidPath(serviceDid), (context) =>
  context.json(exampleServiceDidDocument(serviceDid))
);
app.get("/api/resource", async (context) => {
  const denied = await deniedProtectedResponse(context.req.raw);

  if (denied !== undefined) {
    return denied;
  }

  return context.json(resourceBody());
});
app.post("/api/profile", async (context) => {
  const denied = await deniedProtectedResponse(context.req.raw);

  if (denied !== undefined) {
    return denied;
  }

  return context.json(profileBody());
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
  logExampleServiceUrls(adapterName, listenUrl, serviceDid);
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

async function deniedProtectedResponse(request: Request): Promise<Response | undefined> {
  const status = await authenticateProtectedResource(service, {
    headers: request.headers,
    method: request.method,
    url: request.url
  });

  if (isActiveProtectedResourceAuthentication(status)) {
    return undefined;
  }

  return new Response(JSON.stringify(status.response.body), {
    headers: {
      ...status.response.headers,
      "content-type": status.response.contentType
    },
    status: status.response.status
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

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body, null, 2));
}
