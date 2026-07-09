import type { AepImportableJoseKey } from "./jwt.js";

export type DidWebFetchLike = (input: URL | string, init?: RequestInit) => Promise<Response>;

export interface ResolveDidWebPublicKeyOptions {
  did: string;
  fetch?: DidWebFetchLike;
  kid?: string;
}

export function didWebDocumentUrl(did: string): URL {
  const prefix = "did:web:";

  if (!did.startsWith(prefix)) {
    throw new Error(`Unsupported DID method: ${did}`);
  }

  const [encodedHost, ...pathParts] = did.slice(prefix.length).split(":");

  if (encodedHost === undefined || encodedHost.length === 0) {
    throw new Error(`Invalid did:web identifier: ${did}`);
  }

  const hostName = decodeURIComponent(encodedHost);
  const protocol =
    hostName.startsWith("localhost") || hostName.startsWith("127.0.0.1") ? "http" : "https";
  const documentPath =
    pathParts.length === 0
      ? "/.well-known/did.json"
      : `/${pathParts.map(decodeURIComponent).join("/")}/did.json`;

  return new URL(`${protocol}://${hostName}${documentPath}`);
}

export async function resolveDidWebPublicKey(
  options: ResolveDidWebPublicKeyOptions
): Promise<AepImportableJoseKey> {
  const fetchImpl = options.fetch ?? globalThis.fetch;

  if (typeof fetchImpl !== "function") {
    throw new TypeError("AEP did:web resolution requires a fetch implementation.");
  }

  const document = await fetchJson(didWebDocumentUrl(options.did), fetchImpl);
  const methods = arrayField(document, "verificationMethod").filter(isRecord);
  const method =
    options.kid === undefined
      ? methods.find((candidate) => isRecord(candidate["publicKeyJwk"]))
      : methods.find(
          (candidate) => candidate["id"] === options.kid && isRecord(candidate["publicKeyJwk"])
        );

  if (method === undefined || !isRecord(method["publicKeyJwk"])) {
    throw new Error(`No public JWK found for ${options.kid ?? options.did}.`);
  }

  return method["publicKeyJwk"];
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
