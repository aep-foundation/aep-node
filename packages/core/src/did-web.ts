import type { AepImportableJoseKey } from "./jwt.js";

export type DidWebFetchLike = (input: URL | string, init?: RequestInit) => Promise<Response>;

export interface ResolveDidWebPublicKeyOptions {
  allowInsecureLoopback?: boolean;
  did: string;
  fetch?: DidWebFetchLike;
  kid: string;
}

export interface DidWebDocumentUrlOptions {
  allowInsecureLoopback?: boolean;
}

export function didWebDocumentUrl(did: string, options: DidWebDocumentUrlOptions = {}): URL {
  const prefix = "did:web:";

  if (!did.startsWith(prefix)) {
    throw new Error(`Unsupported DID method: ${did}`);
  }

  const [encodedHost, ...pathParts] = did.slice(prefix.length).split(":");

  if (encodedHost === undefined || encodedHost.length === 0) {
    throw new Error(`Invalid did:web identifier: ${did}`);
  }

  const hostName = decodeURIComponent(encodedHost);
  const documentPath =
    pathParts.length === 0
      ? "/.well-known/did.json"
      : `/${pathParts.map(decodeURIComponent).join("/")}/did.json`;

  const url = new URL(`https://${hostName}${documentPath}`);
  if (options.allowInsecureLoopback === true && isLoopbackHost(url.hostname)) {
    url.protocol = "http:";
  }
  return url;
}

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

  const document = await fetchJson(
    didWebDocumentUrl(options.did, {
      ...(options.allowInsecureLoopback === undefined
        ? {}
        : { allowInsecureLoopback: options.allowInsecureLoopback })
    }),
    fetchImpl
  );
  const methods = arrayField(document, "verificationMethod").filter(isRecord);
  const method = methods.find(
    (candidate) => candidate["id"] === options.kid && isRecord(candidate["publicKeyJwk"])
  );

  if (method === undefined || !isRecord(method["publicKeyJwk"])) {
    throw new Error(`No public JWK found for ${options.kid}.`);
  }

  return method["publicKeyJwk"];
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

async function fetchJson(url: URL, fetchImpl: DidWebFetchLike): Promise<unknown> {
  const response = await fetchImpl(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url.toString()}: ${response.status}`);
  }

  return response.json();
}

function arrayField(value: unknown, field: string): unknown[] {
  if (!isRecord(value)) {
    return [];
  }

  const fieldValue = value[field];
  return Array.isArray(fieldValue) ? fieldValue : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
