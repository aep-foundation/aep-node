import { get as httpGet } from "node:http";
import { get as httpsGet } from "node:https";

import {
  parseAepPortableDocument,
  parseAepServiceDocuments,
  type AepPortableDocument,
  type AepServiceDocument
} from "@aep-foundation/core";

export type AepDocumentReadResult = {
  descriptor: AepServiceDocument;
  webUrl: string;
} & (
  | { status: "portable"; document: AepPortableDocument }
  | { status: "web"; reason: "not_advertised" | "unavailable_or_unsupported" }
);

export interface ReadAepServiceDocumentOptions {
  document: AepServiceDocument;
  signal?: AbortSignal;
  timeoutMs?: number;
}

const maximumBytes = 1024 * 1024;

export async function readAepServiceDocument(
  options: ReadAepServiceDocumentOptions
): Promise<AepDocumentReadResult> {
  const descriptor = options.document;
  parseAepServiceDocuments([descriptor]);
  // Descriptor validation requires an HTML representation with a valid URL.
  const webUrl = descriptor.representations.find((item) => item.media_type === "text/html")
    ?.url as string;
  const portableUrl = descriptor.representations.find(
    (item) => item.media_type === "application/json"
  )?.url;
  const result = { descriptor, webUrl };
  if (portableUrl === undefined) return { ...result, status: "web", reason: "not_advertised" };
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647)
    throw new TypeError("Document timeout must be a positive integer number of milliseconds.");
  const deadline = AbortSignal.timeout(timeoutMs);
  const signal =
    options.signal === undefined ? deadline : AbortSignal.any([options.signal, deadline]);
  try {
    let current = new URL(portableUrl);
    for (let redirects = 0; ; redirects += 1) {
      const response = await download(current, signal);
      if (response.location !== undefined) {
        if (redirects >= 5) throw new TypeError("Document redirect limit exceeded.");
        const next = new URL(response.location, current);
        if (current.protocol === "https:" && next.protocol !== "https:")
          throw new TypeError("Document redirects must not downgrade HTTPS.");
        current = next;
        continue;
      }
      const document = parseAepPortableDocument(JSON.parse(response.text));
      if (document.id !== descriptor.id)
        throw new TypeError("Document ID does not match its descriptor.");
      return { ...result, status: "portable", document };
    }
  } catch {
    options.signal?.throwIfAborted();
    return { ...result, status: "web", reason: "unavailable_or_unsupported" };
  }
}

function download(url: URL, signal: AbortSignal): Promise<{ text: string; location?: string }> {
  signal.throwIfAborted();
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
    url.username ||
    url.password
  )
    throw new TypeError(
      "Document URLs require HTTPS except on loopback hosts, without user information."
    );
  return new Promise((resolve, reject) => {
    const get = url.protocol === "http:" ? httpGet : httpsGet;
    const request = get(
      url,
      {
        agent: false,
        rejectUnauthorized: true,
        signal,
        headers: { Accept: "application/json", "Accept-Encoding": "identity" }
      },
      (response) => {
        const status = response.statusCode ?? 0;
        if ([301, 302, 303, 307, 308].includes(status)) {
          response.destroy();
          if (response.headers.location === undefined)
            reject(new TypeError("Redirect omitted Location."));
          else resolve({ text: "", location: response.headers.location });
          return;
        }
        const contentType = response.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
        const encoding = response.headers["content-encoding"];
        if (
          status < 200 ||
          status >= 300 ||
          contentType !== "application/json" ||
          (encoding !== undefined && encoding !== "identity")
        ) {
          response.destroy();
          reject(new TypeError("Unsupported document response."));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maximumBytes) response.destroy(new TypeError("Document exceeds 1 MiB."));
          else chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () => {
          try {
            resolve({
              text: new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))
            });
          } catch {
            reject(new TypeError("Document response is not valid UTF-8."));
          }
        });
      }
    );
    request.on("error", reject);
  });
}
