import type { AepAssertionOperation, AepSigningAlgorithm } from "./types.js";

/**
 * AEP core sets the maximum client assertion validity interval. A Platform may enforce a
 * shorter local maximum, but never a longer one.
 */
const MAX_ASSERTION_LIFETIME_SECONDS = 300;

export type ManagedAgentStatus = "active" | "revoked" | "suspended" | "terminated";

export interface PlatformDiscoveryDocument {
  aep_version: string;
  endpoints: {
    hosted_verification?: string;
    lifecycle: string;
    list: string;
    provision: string;
    sign: string;
    [key: string]: unknown;
  };
  http: {
    endpoint_base: string;
    [key: string]: unknown;
  };
  identity: {
    did_methods: string[];
    did_url_template: string;
    [key: string]: unknown;
  };
  platform: {
    did?: string;
    hosted_verification: boolean;
    name: string;
    [key: string]: unknown;
  };
  signing: {
    algorithms: AepSigningAlgorithm[];
    default_lifetime_seconds: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface PlatformAgentIdentity {
  agent_did: string;
  agent_identity_id: string;
  created_at: string;
  did_document_url: string;
  key_id: string;
  service_did: string;
  signing_algorithms: AepSigningAlgorithm[];
  status: ManagedAgentStatus;
  updated_at: string;
}

export interface PlatformPage<T> {
  count: string;
  data: T[];
  total: string;
}

export type PlatformAgentIdentityListResponse = PlatformPage<PlatformAgentIdentity>;

export interface PlatformProvisionRequest {
  service_did: string;
}

export interface PlatformProvisionRequestOptions {
  /**
   * The value the caller will send in the `Idempotency-Key` field. Provisioning is
   * state-mutating, so the key is required and must be non-empty.
   */
  idempotencyKey: string;
  serviceDid: string;
}

export interface PlatformSignRequest {
  jti: string;
  lifetime_seconds?: string;
  op: AepAssertionOperation;
  resource?: string;
  platform_context?: Record<string, unknown>;
  service_did: string;
}

export interface PlatformSignRequestOptions {
  command: AepAssertionOperation;
  jti: string;
  maxLifetimeSeconds?: number;
  serviceDid: string;
  resource?: string;
  lifetimeSeconds?: number;
  platformContext?: Record<string, unknown>;
}

export interface PlatformSignCompletedResponse {
  status: "completed";
  agent_did: string;
  client_assertion: string;
  expires_at: string;
  issued_at: string;
  jti: string;
  platform_context?: Record<string, unknown>;
  service_did: string;
}

export interface PlatformSignPendingResponse {
  status: "pending";
  platform_context?: Record<string, unknown>;
  retry_after_seconds: string;
}

export type PlatformSignResponse = PlatformSignCompletedResponse | PlatformSignPendingResponse;

export function createPlatformProvisionRequest(
  options: PlatformProvisionRequestOptions
): PlatformProvisionRequest {
  assertNonEmpty("idempotencyKey", options.idempotencyKey);
  assertNonEmpty("serviceDid", options.serviceDid);

  return {
    service_did: options.serviceDid
  };
}

export function createPlatformSignRequest(
  options: PlatformSignRequestOptions
): PlatformSignRequest {
  assertNonEmpty("jti", options.jti);
  assertNonEmpty("serviceDid", options.serviceDid);
  if ((options.command === "authenticate") !== (options.resource !== undefined)) {
    throw new TypeError("resource is required only for authenticate signing.");
  }
  const lifetimeSeconds =
    options.lifetimeSeconds === undefined
      ? undefined
      : validateLifetimeSeconds(options.lifetimeSeconds, options.maxLifetimeSeconds);

  return {
    jti: options.jti,
    ...(lifetimeSeconds === undefined ? {} : { lifetime_seconds: String(lifetimeSeconds) }),
    op: options.command,
    ...(options.resource === undefined ? {} : { resource: options.resource }),
    ...(options.platformContext === undefined
      ? {}
      : { platform_context: structuredClone(options.platformContext) }),
    service_did: options.serviceDid
  };
}

function assertNonEmpty(label: string, value: string): void {
  if (value.trim().length === 0) {
    throw new TypeError(`${label} must be a non-empty string.`);
  }
}

function validateLifetimeSeconds(
  lifetimeSeconds: number,
  maxLifetimeSeconds = MAX_ASSERTION_LIFETIME_SECONDS
): number {
  if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds <= 0) {
    throw new TypeError("lifetimeSeconds must be a positive integer.");
  }

  if (!Number.isInteger(maxLifetimeSeconds) || maxLifetimeSeconds <= 0) {
    throw new TypeError("maxLifetimeSeconds must be a positive integer.");
  }

  const effectiveMaximum = Math.min(maxLifetimeSeconds, MAX_ASSERTION_LIFETIME_SECONDS);

  if (lifetimeSeconds > effectiveMaximum) {
    throw new TypeError(`lifetimeSeconds must not exceed ${String(effectiveMaximum)} seconds.`);
  }

  return lifetimeSeconds;
}
