import { AEP_BUILT_IN_GRANT_TYPES, didWebDocumentUrl } from "@aep-foundation/core";
import type { AepBuiltInGrantResponse, AepBuiltInGrantType } from "@aep-foundation/core";
import type {
  AepServiceCredentialRecord,
  AepServiceCredentialStore,
  AepServiceOptions
} from "@aep-foundation/service";
import {
  createInMemoryClientAssertionReplayStore,
  createInMemoryCommandIdempotencyStore,
  createInMemoryEnrollmentStore,
  createStaticEnrollmentPolicy
} from "@aep-foundation/service";

export function exampleListenUrl(host: string, port: number): string {
  return `http://${host}:${port}`;
}

export function exampleServiceDidDocument(serviceDid: string): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: serviceDid
  };
}

export function exampleServiceDidPath(serviceDid: string): string {
  return didWebDocumentUrl(serviceDid, { allowInsecureLoopback: true }).pathname;
}

export function logExampleServiceUrls(
  service: string,
  listenUrl: string,
  serviceDid: string
): void {
  console.log(`AEP ${service} service listening on ${listenUrl}`);
  console.log(`Service DID: ${serviceDid}`);
  console.log(
    `Service DID document: ${String(didWebDocumentUrl(serviceDid, { allowInsecureLoopback: true }))}`
  );
  console.log("AEP discovery:");
  console.log(`  GET  ${listenUrl}/.well-known/aep`);
  console.log(`  GET  ${listenUrl}/openapi.json`);
  console.log("Protected resources:");
  console.log(`  GET  ${listenUrl}/api/resource`);
  console.log(`  POST ${listenUrl}/api/profile`);
}

export function exampleOpenApi(authenticationMethod: string): Record<string, unknown> {
  return {
    openapi: "3.1.0",
    info: { title: "AEP example protected resources", version: "1.0.0" },
    components: {
      securitySchemes: {
        aep: {
          type: "http",
          scheme: "bearer",
          "x-aep-authentication-method": authenticationMethod
        }
      }
    },
    security: [{ aep: [] }],
    paths: {
      "/api/resource": { get: { responses: { "200": { description: "Protected resource" } } } },
      "/api/profile": { post: { responses: { "200": { description: "Protected profile" } } } }
    }
  };
}

export function exampleOpenApiAdvertisement(): Pick<AepServiceOptions, "openapi"> {
  return { openapi: { url: "/openapi.json", pathMatching: { trailingSlash: "strict" } } };
}

export function requiredExampleConfig(name: string, value: string | undefined): string {
  if (value === undefined || value.length === 0) {
    throw new Error(`Missing required example configuration: ${name}`);
  }

  return value;
}

export async function findActiveCredential(
  store: AepServiceCredentialStore,
  agentDid: string,
  grantType: AepBuiltInGrantType,
  matches: (credential: AepBuiltInGrantResponse) => boolean
): Promise<AepServiceCredentialRecord | undefined> {
  const now = Date.now();
  const records = await store.listCredentials(agentDid, grantType);

  return records.find(
    (record) =>
      record.revokedAt === undefined &&
      Date.parse(record.expiresAt) > now &&
      matches(record.credential)
  );
}

export function resourceBody(): Record<string, unknown> {
  return {
    widgets: [1, 2, 3]
  };
}

export function profileBody(): Record<string, unknown> {
  return {
    status: "received"
  };
}

export function exampleServicePorts(): Pick<
  AepServiceOptions,
  | "clientAssertion"
  | "commandIdempotencyStore"
  | "enrollmentPolicy"
  | "enrollmentStore"
  | "replayStore"
> {
  return {
    clientAssertion: { allowInsecureLoopback: true },
    commandIdempotencyStore: createInMemoryCommandIdempotencyStore(),
    enrollmentPolicy: createStaticEnrollmentPolicy(),
    enrollmentStore: createInMemoryEnrollmentStore(),
    replayStore: createInMemoryClientAssertionReplayStore()
  };
}

export function isExampleServiceInteractionPath(pathOrUrl: string | undefined): boolean {
  const path = pathFromUrl(pathOrUrl);

  return (
    path === "/.well-known/aep" ||
    path === "/openapi.json" ||
    path.startsWith("/aep/") ||
    path.startsWith("/api/")
  );
}

export function logExampleServiceInteraction(
  service: string,
  method: string | undefined,
  pathOrUrl: string | undefined,
  status: number
): void {
  const path = pathFromUrl(pathOrUrl);

  if (!isExampleServiceInteractionPath(path)) {
    return;
  }

  console.log(
    [
      `Service interaction`,
      `service=${service}`,
      `method=${method ?? "unknown"}`,
      `path=${path}`,
      `status=${status}`
    ].join(" ")
  );
}

export function logExampleCredentialIssued(
  service: string,
  grantType: AepBuiltInGrantType,
  agentDid: string,
  credentialId: string
): void {
  console.log(
    [
      "Issued Service credential",
      `service=${service}`,
      `grant_type=${grantType}`,
      `agent_did=${agentDid}`,
      `credential_id=${credentialId}`
    ].join(" ")
  );
}

export function parsePort(value: string): number {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    throw new TypeError(`Invalid PORT: ${value}`);
  }

  return parsed;
}

export function isBuiltInGrantType(value: string): value is AepBuiltInGrantType {
  return AEP_BUILT_IN_GRANT_TYPES.includes(value as AepBuiltInGrantType);
}

export function stringField(value: unknown, field: string): string {
  if (!isRecord(value) || typeof value[field] !== "string") {
    throw new Error(`Expected string field: ${field}`);
  }

  return value[field];
}

export function recordField(value: unknown, field: string): Record<string, unknown> {
  if (!isRecord(value) || !isRecord(value[field])) {
    throw new Error(`Expected object field: ${field}`);
  }

  return value[field];
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function pathFromUrl(pathOrUrl: string | undefined): string {
  if (pathOrUrl === undefined || pathOrUrl.length === 0) {
    return "/";
  }

  return new URL(pathOrUrl, "http://example.local").pathname;
}
