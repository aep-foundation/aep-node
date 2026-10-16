import type { AepImportableJoseKey } from "./jwt.js";

export type DidWebFetchLike = (input: URL | string, init?: RequestInit) => Promise<Response>;

export interface ResolveDidWebPublicKeyOptions {
  allowInsecureLoopback?: boolean;
  did: string;
  fetch?: DidWebFetchLike;
  kid: string;
  /** Maximum decoded DID document size, in bytes. Defaults to 256 KiB. */
  maxBytes?: number;
}

export interface DidWebDocumentUrlOptions {
  allowInsecureLoopback?: boolean;
}

const DID_WEB_PREFIX = "did:web:";
const DEFAULT_MAX_DOCUMENT_BYTES = 256 * 1024;

/**
 * Host, optionally with a port, as `did:web` percent-decodes to. Anything that could shift the
 * request to another origin — userinfo, a path, a query, a fragment, a second colon — is
 * rejected rather than handed to the URL parser, which would silently reinterpret it.
 */
const HOST_PATTERN = /^(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$/;

/**
 * One path segment of a `did:web` identifier after percent-decoding. `/`, `?`, `#`, `\`, and
 * the dot segments are excluded so a segment cannot escape the path it was resolved into.
 */
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9\-._~!$&'()*+,;=:@%]+$/;

export function didWebDocumentUrl(did: string, options: DidWebDocumentUrlOptions = {}): URL {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new Error(`Unsupported DID method: ${did}`);
  }

  const [encodedHost, ...encodedPathParts] = did.slice(DID_WEB_PREFIX.length).split(":");

  if (encodedHost === undefined || encodedHost.length === 0) {
    throw new Error(`Invalid did:web identifier: ${did}`);
  }

  const hostName = decodeComponent(encodedHost, did);

  if (!HOST_PATTERN.test(hostName)) {
    throw new Error(`Invalid did:web host: ${did}`);
  }

  const pathParts = encodedPathParts.map((part) => {
    const segment = decodeComponent(part, did);

    if (!PATH_SEGMENT_PATTERN.test(segment) || segment === "." || segment === "..") {
      throw new Error(`Invalid did:web path segment: ${did}`);
    }

    // Preserve escapes so URL parsing cannot reinterpret a decoded value as a dot segment.
    return part;
  });

  const documentPath =
    pathParts.length === 0 ? "/.well-known/did.json" : `/${pathParts.join("/")}/did.json`;

  let url: URL;

  try {
    url = new URL(`https://${hostName}${documentPath}`);
  } catch {
    throw new Error(`Invalid did:web host: ${did}`);
  }

  if (url.hostname !== normalizedHostname(hostName) || url.username !== "" || url.password !== "") {
    throw new Error(`Invalid did:web host: ${did}`);
  }

  if (options.allowInsecureLoopback === true && isLoopbackHost(url.hostname)) {
    url.protocol = "http:";
  }

  return url;
}

/**
 * Resolves the public JWK that a `did:web` Agent DID publishes for `kid`.
 *
 * The resolved document must identify the same DID that was requested, and only the
 * verification method referenced by `kid` is considered, so a document that publishes several
 * keys cannot substitute one the assertion did not name.
 */
export async function resolveDidWebPublicKey(
  options: ResolveDidWebPublicKeyOptions
): Promise<AepImportableJoseKey> {
  const fetchImpl = options.fetch ?? globalThis.fetch;

  if (typeof fetchImpl !== "function") {
    throw new TypeError("AEP did:web resolution requires a fetch implementation.");
  }

  const fragment = options.kid.indexOf("#");
  const kidDid = fragment === -1 ? options.kid : options.kid.slice(0, fragment);

  if (kidDid !== options.did) {
    throw new Error("AEP did:web kid does not identify the assertion issuer.");
  }

  const url = didWebDocumentUrl(options.did, {
    ...(options.allowInsecureLoopback === undefined
      ? {}
      : { allowInsecureLoopback: options.allowInsecureLoopback })
  });
  const document = await fetchJson(url, fetchImpl, options.maxBytes ?? DEFAULT_MAX_DOCUMENT_BYTES);

  if (!isRecord(document) || document["id"] !== options.did) {
    throw new Error(`The did:web document at ${url.toString()} does not identify ${options.did}.`);
  }

  const relativeKid = fragment === -1 ? undefined : options.kid.slice(fragment);
  const methods = document["verificationMethod"];
  const method = (Array.isArray(methods) ? methods : [])
    .filter(isRecord)
    .find(
      (candidate) =>
        (candidate["id"] === options.kid ||
          (relativeKid !== undefined && candidate["id"] === relativeKid)) &&
        isRecord(candidate["publicKeyJwk"])
    );
  const publicKeyJwk = method?.["publicKeyJwk"];

  if (!isRecord(publicKeyJwk)) {
    throw new Error(`No public JWK found for ${options.kid}.`);
  }

  return publicKeyJwk;
}

function decodeComponent(value: string, did: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error(`Invalid did:web identifier: ${did}`);
  }
}

function normalizedHostname(hostName: string): string {
  if (hostName.startsWith("[")) {
    const close = hostName.indexOf("]");
    return (close === -1 ? hostName : hostName.slice(0, close + 1)).toLowerCase();
  }

  const portSeparator = hostName.lastIndexOf(":");
  return (portSeparator === -1 ? hostName : hostName.slice(0, portSeparator)).toLowerCase();
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

/**
 * Fetches a DID document without following redirects.
 *
 * A redirect could move resolution to an origin the DID does not encode, so a redirected
 * response is an error rather than something to chase.
 */
async function fetchJson(url: URL, fetchImpl: DidWebFetchLike, maxBytes: number): Promise<unknown> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("maxBytes must be a positive safe integer.");
  }
  const response = await fetchImpl(url, { redirect: "error" });

  if (response.redirected || (response.status >= 300 && response.status < 400)) {
    throw new Error(`Refusing to follow a did:web redirect from ${url.toString()}.`);
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url.toString()}: ${response.status}`);
  }

  const reader: ReadableStreamDefaultReader<Uint8Array> | undefined = response.body?.getReader();
  const decoder = new TextDecoder();
  let body = "";
  let size = 0;
  if (reader !== undefined) {
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > maxBytes) {
          await reader.cancel();
          throw new Error(
            `The did:web document at ${url.toString()} exceeded ${String(maxBytes)} bytes.`
          );
        }
        body += decoder.decode(part.value, { stream: true });
      }
      body += decoder.decode();
    } finally {
      reader.releaseLock();
    }
  }

  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error(`The did:web document at ${url.toString()} is not valid JSON.`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
