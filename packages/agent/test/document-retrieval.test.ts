import { EventEmitter } from "node:events";
import { IncomingMessage } from "node:http";
import type * as NodeHttp from "node:http";
import { Socket } from "node:net";
import type { RequestOptions } from "node:https";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AepValidationError, type AepServiceDocument } from "@aep-foundation/core";
import { readAepServiceDocument } from "../src/service-documents.js";

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("node:https", () => ({ get: mocks.get }));
vi.mock("node:http", async (importOriginal) => ({
  ...(await importOriginal<typeof NodeHttp>()),
  get: mocks.get
}));

const descriptor: AepServiceDocument = {
  id: "terms",
  type: "terms_of_service",
  title: "Terms",
  enrollment: "required",
  representations: [
    { media_type: "text/html", url: "https://example.com/terms" },
    { media_type: "application/json", url: "https://documents.example.com/terms.json" }
  ]
};
const content = {
  format: "aep-service-document",
  version: "1.0",
  id: "terms",
  content: [{ type: "paragraph", text: "Full service text." }]
};
interface Reply {
  status?: number;
  headers?: Record<string, string>;
  body?: string | Buffer;
  error?: Error;
  stall?: boolean;
}
let replies: Reply[];
let requests: { url: URL; options: RequestOptions }[];

beforeEach(() => {
  replies = [{}];
  requests = [];
  mocks.get.mockImplementation(
    (url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void) => {
      requests.push({ url, options });
      const reply = replies.shift() ?? {};
      const request = new EventEmitter();
      const state = { destroyed: false };
      const destroy = (error: Error) => {
        state.destroyed = true;
        request.emit("error", error);
      };
      Object.assign(request, { destroy });
      const aborted = () => destroy(new Error("Aborted"));
      options.signal?.addEventListener("abort", aborted, { once: true });
      queueMicrotask(() => {
        if (state.destroyed) return;
        const socket = new Socket();
        if (reply.stall) return;
        if (reply.error) {
          destroy(reply.error);
          return;
        }
        const response = new IncomingMessage(socket);
        response.statusCode = reply.status ?? 200;
        response.headers = reply.headers ?? { "content-type": "application/json; charset=utf-8" };
        callback(response);
        if (!response.destroyed) {
          response.push(reply.body ?? JSON.stringify(content));
          response.push(null);
        }
        options.signal?.removeEventListener("abort", aborted);
      });
      return request;
    }
  );
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("anonymous Service Document retrieval", () => {
  it.each([
    { representations: [] },
    {
      representations: [{ media_type: "application/json", url: "https://example.com/terms.json" }]
    },
    { representations: [{ media_type: "text/html", url: "http://example.com/terms" }] }
  ])("rejects invalid representations before making a request: %j", async ({ representations }) => {
    await expect(
      readAepServiceDocument({ document: { ...descriptor, representations } })
    ).rejects.toThrow(AepValidationError);
    expect(mocks.get).not.toHaveBeenCalled();
  });

  it("uses standard hostname resolution, reads UTF-8 and sends no credentials", async () => {
    const result = await readAepServiceDocument({ document: descriptor });
    expect(result).toEqual({
      descriptor,
      webUrl: "https://example.com/terms",
      status: "portable",
      document: content
    });
    expect(requests[0]?.options.headers).toEqual({
      Accept: "application/json",
      "Accept-Encoding": "identity"
    });
    expect(requests[0]?.options.agent).toBe(false);
    expect(requests[0]?.options.lookup).toBeUndefined();
    expect(requests[0]?.options.rejectUnauthorized).toBe(true);
  });

  it("supports public cross-origin redirects without forwarding cookies", async () => {
    replies = [
      {
        status: 302,
        headers: { location: "https://cdn.example.org/doc", "set-cookie": "private=1" }
      },
      {}
    ];
    expect((await readAepServiceDocument({ document: descriptor })).status).toBe("portable");
    expect(requests[1]?.url.origin).toBe("https://cdn.example.org");
    expect(requests[1]?.options.headers).toEqual(requests[0]?.options.headers);
  });

  it.each([
    "http://example.org",
    "https://user:password@example.org",
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "ftp://example.org"
  ])("rejects unsafe redirect %s before connecting", async (location) => {
    replies = [{ status: 302, headers: { location } }];
    expect((await readAepServiceDocument({ document: descriptor })).status).toBe("web");
    expect(requests).toHaveLength(1);
  });

  it.each(["https://127.0.0.1", "https://[::1]", "https://192.168.1.10"])(
    "does not impose address restrictions on %s",
    async (location) => {
      replies = [{ status: 302, headers: { location } }, {}];
      expect((await readAepServiceDocument({ document: descriptor })).status).toBe("portable");
    }
  );

  it.each(["http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"])(
    "permits loopback development at %s",
    async (origin) => {
      const local = {
        ...descriptor,
        representations: descriptor.representations.map((item) => ({
          ...item,
          url: `${origin}/terms`
        }))
      };
      replies = [{ status: 302, headers: { location: "/document" } }, {}];
      expect((await readAepServiceDocument({ document: local })).status).toBe("portable");
      expect(requests[1]?.url.href).toBe(`${origin}/document`);
    }
  );

  it("rejects non-loopback HTTP redirects from local development", async () => {
    const local = {
      ...descriptor,
      representations: descriptor.representations.map((item) => ({
        ...item,
        url: "http://localhost:8080/terms"
      }))
    };
    replies = [{ status: 302, headers: { location: "http://example.com/document" } }];
    expect((await readAepServiceDocument({ document: local })).status).toBe("web");
    expect(requests).toHaveLength(1);
  });

  it.for([
    { status: 500 },
    { status: 302, headers: {} },
    { headers: { "content-type": "text/html" } },
    { headers: { "content-type": "application/json", "content-encoding": "gzip" } },
    { body: "not json" },
    { body: Buffer.from([0xc3, 0x28]) },
    { body: "x".repeat(1024 * 1024 + 1) },
    { body: JSON.stringify({ ...content, id: "different" }) },
    { body: JSON.stringify({ ...content, content: [{ type: "unknown" }] }) },
    { error: new Error("connection failed") }
  ])("offers the HTML link instead of partial or unsupported content", async (reply) => {
    replies = [reply];
    expect(await readAepServiceDocument({ document: descriptor })).toMatchObject({
      status: "web",
      webUrl: "https://example.com/terms",
      reason: "unavailable_or_unsupported"
    });
  });

  it("bounds redirects and handles connection failures", async () => {
    replies = Array.from({ length: 6 }, () => ({ status: 302, headers: { location: "/again" } }));
    expect((await readAepServiceDocument({ document: descriptor })).status).toBe("web");
    expect(requests).toHaveLength(6);
    replies = [{ error: new Error("DNS failure") }];
    expect((await readAepServiceDocument({ document: descriptor })).status).toBe("web");
  });

  it("uses a finite total timeout and respects caller cancellation", async () => {
    replies = [{ stall: true }, { stall: true }];
    expect((await readAepServiceDocument({ document: descriptor, timeoutMs: 10 })).status).toBe(
      "web"
    );
    const abort = new AbortController();
    const result = readAepServiceDocument({ document: descriptor, signal: abort.signal });
    abort.abort(new Error("User cancelled"));
    await expect(result).rejects.toThrow("User cancelled");
    await expect(readAepServiceDocument({ document: descriptor, timeoutMs: 0 })).rejects.toThrow(
      "timeout"
    );
  });

  it("does not fetch a web-only descriptor", async () => {
    const result = await readAepServiceDocument({
      document: {
        ...descriptor,
        representations: descriptor.representations.filter(
          (item) => item.media_type === "text/html"
        )
      }
    });
    expect(result).toMatchObject({ status: "web", reason: "not_advertised" });
    expect(mocks.get).not.toHaveBeenCalled();
  });
});
