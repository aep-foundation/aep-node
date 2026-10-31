import { once } from "node:events";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { expect, it } from "vitest";
import { readAepServiceDocument } from "../src/service-documents.js";

it("downloads from a real loopback HTTP server without forwarding cookies", async () => {
  const requests: IncomingHttpHeaders[] = [];
  const server = createServer((request, response) => {
    requests.push({ ...request.headers });
    if (request.url === "/terms") {
      response.writeHead(302, { location: "/document", "set-cookie": "session=private" });
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        format: "aep-service-document",
        version: "1.0",
        id: "terms",
        content: [{ type: "paragraph", text: "Full terms." }]
      })
    );
  });
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const url = `http://127.0.0.1:${address.port}/terms`;
    const result = await readAepServiceDocument({
      document: {
        id: "terms",
        type: "terms_of_service",
        title: "Terms",
        enrollment: "required",
        representations: [
          { media_type: "text/html", url },
          { media_type: "application/json", url }
        ]
      }
    });
    expect(result.status).toBe("portable");
    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(request.cookie).toBeUndefined();
      expect(request.authorization).toBeUndefined();
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
