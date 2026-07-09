import { AEP_BUILT_IN_GRANT_TYPES } from "@aep-foundation/core";
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

export function resourceBody(adapter: string): Record<string, unknown> {
  return {
    adapter,
    message: "This resource was returned after AEP credential authentication.",
    resource: "example-resource"
  };
}

export function profileBody(adapter: string, profile: unknown): Record<string, unknown> {
  return {
    adapter,
    profile,
    updated: true
  };
}

export function exampleServicePorts(): Pick<
  AepServiceOptions,
  "commandIdempotencyStore" | "enrollmentPolicy" | "enrollmentStore" | "replayStore"
> {
  return {
    commandIdempotencyStore: createInMemoryCommandIdempotencyStore(),
    enrollmentPolicy: createStaticEnrollmentPolicy(),
    enrollmentStore: createInMemoryEnrollmentStore(),
    replayStore: createInMemoryClientAssertionReplayStore()
  };
}

export function isExampleServiceInteractionPath(pathOrUrl: string | undefined): boolean {
  const path = pathFromUrl(pathOrUrl);

  return path === "/.well-known/aep" || path.startsWith("/aep/") || path.startsWith("/api/");
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
