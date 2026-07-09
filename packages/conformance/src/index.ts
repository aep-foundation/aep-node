import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

import {
  parseBuiltInGrantResponse,
  parseEnrollRequest,
  parseEnrollResponse,
  parseGrantRequest,
  parseInspectDocument,
  parseProblemDetails,
  parseRevokeRequest,
  parseRevokeResponse,
  parseStatusResponse,
  validateBuiltInGrantResponse,
  validateEnrollRequest,
  validateEnrollResponse,
  validateGrantRequest,
  validateInspectDocument,
  validateProblemDetails,
  validateRevokeRequest,
  validateRevokeResponse,
  validateStatusResponse
} from "@aep-foundation/core";
import type {
  AepBuiltInGrantResponse,
  AepGrantType,
  AepProblemDetails,
  EnrollRequest,
  EnrollResponse,
  GrantRequest,
  InspectDocument,
  RevokeRequest,
  RevokeResponse,
  StatusResponse,
  ValidationIssue,
  ValidationResult
} from "@aep-foundation/core";

const requireFromCwd = createRequire(`${process.cwd()}/`);
const packageRoot = path.dirname(
  requireFromCwd.resolve("@aep-foundation/conformance/package.json")
);

export const specArtifactsRoot = path.join(packageRoot, "fixtures/aep-specs");
export const schemaArtifactsRoot = path.join(specArtifactsRoot, "schemas");
export const testVectorArtifactsRoot = path.join(specArtifactsRoot, "test-vectors");
export const specArtifactManifestPath = path.join(specArtifactsRoot, "manifest.json");

export interface SpecArtifactManifest {
  source: string;
  generated_by: string;
  artifacts: {
    schemas: string[];
    "test-vectors": string[];
  };
}

export interface AepTestVector<TInput = unknown, TExpected = unknown> {
  id: string;
  title?: string;
  description?: string;
  drafts?: string[];
  category?: string;
  applies_to?: string[];
  profile?: string;
  input: TInput;
  expected: TExpected;
  [key: string]: unknown;
}

export class AepConformanceError extends Error {
  readonly issues: ValidationIssue[];

  constructor(message: string, issues: ValidationIssue[]) {
    super(message);
    this.name = "AepConformanceError";
    this.issues = issues;
  }
}

export async function loadSpecArtifactManifest(): Promise<SpecArtifactManifest> {
  return readJson<SpecArtifactManifest>(specArtifactManifestPath);
}

export function schemaArtifactPath(relativePath: string): string {
  return path.join(schemaArtifactsRoot, relativePath);
}

export function testVectorArtifactPath(relativePath: string): string {
  return path.join(testVectorArtifactsRoot, relativePath);
}

export async function loadSchemaArtifact<T = unknown>(relativePath: string): Promise<T> {
  return readJson<T>(schemaArtifactPath(relativePath));
}

export async function loadTestVector<TInput = unknown, TExpected = unknown>(
  relativePath: string
): Promise<AepTestVector<TInput, TExpected>> {
  return readJson<AepTestVector<TInput, TExpected>>(testVectorArtifactPath(relativePath));
}

export function validateInspectConformance(value: unknown): ValidationResult<InspectDocument> {
  return validateInspectDocument(value);
}

export function validateEnrollRequestConformance(value: unknown): ValidationResult<EnrollRequest> {
  return validateEnrollRequest(value);
}

export function validateEnrollResponseConformance(
  value: unknown
): ValidationResult<EnrollResponse> {
  return validateEnrollResponse(value);
}

export function validateStatusResponseConformance(
  value: unknown
): ValidationResult<StatusResponse> {
  return validateStatusResponse(value);
}

export function validateGrantRequestConformance(value: unknown): ValidationResult<GrantRequest> {
  return validateGrantRequest(value);
}

export function validateRevokeRequestConformance(value: unknown): ValidationResult<RevokeRequest> {
  return validateRevokeRequest(value);
}

export function validateRevokeResponseConformance(
  value: unknown
): ValidationResult<RevokeResponse> {
  return validateRevokeResponse(value);
}

export function validateBuiltInGrantResponseConformance(
  grantType: AepGrantType,
  value: unknown
): ValidationResult<AepBuiltInGrantResponse> {
  return validateBuiltInGrantResponse(grantType, value);
}

export function validateProblemDetailsConformance(
  value: unknown
): ValidationResult<AepProblemDetails> {
  return validateProblemDetails(value);
}

export function assertInspectConformance(value: unknown): InspectDocument {
  const result = validateInspectDocument(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Inspect document failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertEnrollRequestConformance(value: unknown): EnrollRequest {
  const result = validateEnrollRequest(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Enroll request failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertEnrollResponseConformance(value: unknown): EnrollResponse {
  const result = validateEnrollResponse(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Enroll response failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertStatusResponseConformance(value: unknown): StatusResponse {
  const result = validateStatusResponse(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Status response failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertGrantRequestConformance(value: unknown): GrantRequest {
  const result = validateGrantRequest(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Grant request failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertRevokeRequestConformance(value: unknown): RevokeRequest {
  const result = validateRevokeRequest(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Revoke request failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertRevokeResponseConformance(value: unknown): RevokeResponse {
  const result = validateRevokeResponse(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Revoke response failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertBuiltInGrantResponseConformance(
  grantType: AepGrantType,
  value: unknown
): AepBuiltInGrantResponse {
  const result = validateBuiltInGrantResponse(grantType, value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Grant response failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export function assertProblemDetailsConformance(value: unknown): AepProblemDetails {
  const result = validateProblemDetails(value);

  if (!result.ok) {
    throw new AepConformanceError(
      "Problem Details response failed AEP conformance validation.",
      result.issues
    );
  }

  return result.value;
}

export async function loadMinimalInspectTestVector(): Promise<
  AepTestVector<Record<string, never>, InspectDocument>
> {
  const vector = await loadTestVector<Record<string, never>, unknown>("inspect/minimal-http.json");

  return {
    ...vector,
    expected: parseInspectDocument(vector.expected)
  };
}

export async function loadMinimalEnrollRequestTestVector(): Promise<
  AepTestVector<EnrollRequest, Record<string, unknown>>
> {
  const vector = await loadTestVector<unknown, Record<string, unknown>>(
    "enroll/request-minimal.json"
  );

  return {
    ...vector,
    input: parseEnrollRequest(vector.input)
  };
}

export async function loadActiveEnrollResponseTestVector(): Promise<
  AepTestVector<
    Record<string, unknown>,
    { body: EnrollResponse; content_type: string; status: number }
  >
> {
  const vector = await loadTestVector<
    Record<string, unknown>,
    { body: unknown; content_type: string; status: number }
  >("enroll/response-active.json");

  return {
    ...vector,
    expected: {
      ...vector.expected,
      body: parseEnrollResponse(vector.expected.body)
    }
  };
}

export async function loadActiveStatusResponseTestVector(): Promise<
  AepTestVector<
    Record<string, unknown>,
    { body: StatusResponse; content_type: string; status: number }
  >
> {
  const vector = await loadTestVector<
    Record<string, unknown>,
    { body: unknown; content_type: string; status: number }
  >("status/response-active.json");

  return {
    ...vector,
    expected: {
      ...vector.expected,
      body: parseStatusResponse(vector.expected.body)
    }
  };
}

export async function loadOAuthBearerGrantRequestTestVector(): Promise<
  AepTestVector<GrantRequest, AepCommandRequestExpectation<GrantRequest>>
> {
  const vector = await loadTestVector<unknown, AepCommandRequestExpectation<unknown>>(
    "grant-revoke/grant-request-oauth-bearer.json"
  );

  return {
    ...vector,
    input: parseGrantRequest(vector.input),
    expected: {
      ...vector.expected,
      body: parseGrantRequest(vector.expected.body)
    }
  };
}

export async function loadOAuthBearerRevokeRequestTestVector(): Promise<
  AepTestVector<RevokeRequest, AepCommandRequestExpectation<RevokeRequest>>
> {
  const vector = await loadTestVector<unknown, AepCommandRequestExpectation<unknown>>(
    "grant-revoke/revoke-request-oauth-bearer.json"
  );

  return {
    ...vector,
    input: parseRevokeRequest(vector.input),
    expected: {
      ...vector.expected,
      body: parseRevokeRequest(vector.expected.body)
    }
  };
}

export async function loadAllGrantTypesRevokeRequestTestVector(): Promise<
  AepTestVector<
    RevokeRequest,
    AepCommandRequestExpectation<RevokeRequest> & {
      must_not_contain?: string[];
    }
  >
> {
  const vector = await loadTestVector<
    unknown,
    AepCommandRequestExpectation<unknown> & {
      must_not_contain?: string[];
    }
  >("grant-revoke/revoke-request-all-grant-types.json");

  return {
    ...vector,
    input: parseRevokeRequest(vector.input),
    expected: {
      ...vector.expected,
      body: parseRevokeRequest(vector.expected.body)
    }
  };
}

export async function loadEmptyRevokeResponseTestVector(): Promise<
  AepTestVector<Record<string, unknown>, AepCommandResponseExpectation<RevokeResponse>>
> {
  const vector = await loadTestVector<
    Record<string, unknown>,
    AepCommandResponseExpectation<unknown>
  >("grant-revoke/revoke-response-empty.json");

  return {
    ...vector,
    expected: {
      ...vector.expected,
      body: parseRevokeResponse(vector.expected.body)
    }
  };
}

export async function loadOAuthBearerGrantResponseTestVector(): Promise<
  AepTestVector<GrantRequest, AepBuiltInGrantResponse>
> {
  return loadBuiltInGrantResponseTestVector(
    "oauth-bearer",
    "credentials/oauth-bearer/grant-response.json"
  );
}

export async function loadApiKeyGrantResponseTestVector(): Promise<
  AepTestVector<GrantRequest, AepBuiltInGrantResponse>
> {
  return loadBuiltInGrantResponseTestVector("api-key", "credentials/api-key/grant-response.json");
}

export async function loadBasicGrantResponseTestVector(): Promise<
  AepTestVector<GrantRequest, AepBuiltInGrantResponse>
> {
  return loadBuiltInGrantResponseTestVector("basic", "credentials/basic/grant-response.json");
}

export async function loadNotRecognizedProblemTestVector(): Promise<
  AepTestVector<{ failure_class: string }, AepCommandResponseExpectation<AepProblemDetails>>
> {
  return loadProblemDetailsResponseTestVector<{ failure_class: string }>(
    "errors/not-recognized-problem.json"
  );
}

export async function loadEnrollIdempotencyConflictTestVector(): Promise<
  AepTestVector<AepEnrollIdempotencyConflictInput, AepCommandResponseExpectation<AepProblemDetails>>
> {
  return loadProblemDetailsResponseTestVector<AepEnrollIdempotencyConflictInput>(
    "idempotency/enroll-conflict.json"
  );
}

export function loadPlatformDiscoveryTestVector(): Promise<
  AepTestVector<Record<string, never>, Record<string, unknown>>
> {
  return loadTestVector<Record<string, never>, Record<string, unknown>>("platform/discovery.json");
}

export function loadPlatformProvisionRequestTestVector(): Promise<
  AepTestVector<Record<string, unknown>, Record<string, never>>
> {
  return loadTestVector<Record<string, unknown>, Record<string, never>>(
    "platform/provision-request.json"
  );
}

export function loadPlatformProvisionResponseTestVector(): Promise<
  AepTestVector<Record<string, never>, Record<string, unknown>>
> {
  return loadTestVector<Record<string, never>, Record<string, unknown>>(
    "platform/provision-response.json"
  );
}

export function loadPlatformListResponseTestVector(): Promise<
  AepTestVector<Record<string, unknown>, Record<string, unknown>>
> {
  return loadTestVector<Record<string, unknown>, Record<string, unknown>>(
    "platform/list-response.json"
  );
}

export function loadPlatformLifecycleRequestTestVector(): Promise<
  AepTestVector<Record<string, unknown>, Record<string, never>>
> {
  return loadTestVector<Record<string, unknown>, Record<string, never>>(
    "platform/lifecycle-request.json"
  );
}

export function loadPlatformLifecycleResponseTestVector(): Promise<
  AepTestVector<Record<string, never>, Record<string, unknown>>
> {
  return loadTestVector<Record<string, never>, Record<string, unknown>>(
    "platform/lifecycle-response.json"
  );
}

export function loadPlatformSignRequestTestVector(): Promise<
  AepTestVector<Record<string, unknown>, Record<string, never>>
> {
  return loadTestVector<Record<string, unknown>, Record<string, never>>(
    "platform/sign-request.json"
  );
}

export function loadPlatformSignResponseTestVector(): Promise<
  AepTestVector<Record<string, never>, Record<string, unknown>>
> {
  return loadTestVector<Record<string, never>, Record<string, unknown>>(
    "platform/sign-response.json"
  );
}

export function loadPlatformVerificationRequestTestVector(): Promise<
  AepTestVector<Record<string, unknown>, Record<string, never>>
> {
  return loadTestVector<Record<string, unknown>, Record<string, never>>(
    "platform/verification-request.json"
  );
}

export function loadPlatformVerificationResponseRecognizedTestVector(): Promise<
  AepTestVector<Record<string, never>, Record<string, unknown>>
> {
  return loadTestVector<Record<string, never>, Record<string, unknown>>(
    "platform/verification-response-recognized.json"
  );
}

export function loadPlatformVerificationResponseUnrecognizedTestVector(): Promise<
  AepTestVector<Record<string, never>, Record<string, unknown>>
> {
  return loadTestVector<Record<string, never>, Record<string, unknown>>(
    "platform/verification-response-unrecognized.json"
  );
}

async function readJson<T>(file: string): Promise<T> {
  return JSON.parse(await readFile(file, "utf8")) as T;
}

interface AepCommandRequestExpectation<TBody> {
  authorization_scheme: string;
  body: TBody;
  client_assertion_op: string;
  content_type: string;
  method: string;
  path: string;
}

export interface AepCommandResponseExpectation<TBody> {
  body: TBody;
  content_type: string;
  status: number;
}

export interface AepEnrollIdempotencyConflictInput {
  agent_did: string;
  first_body_hash: string;
  idempotency_key: string;
  second_body_hash: string;
}

async function loadBuiltInGrantResponseTestVector(
  grantType: AepGrantType,
  relativePath: string
): Promise<AepTestVector<GrantRequest, AepBuiltInGrantResponse>> {
  const vector = await loadTestVector<unknown, unknown>(relativePath);

  return {
    ...vector,
    input: parseGrantRequest(vector.input),
    expected: parseBuiltInGrantResponse(grantType, vector.expected)
  };
}

async function loadProblemDetailsResponseTestVector<TInput>(
  relativePath: string
): Promise<AepTestVector<TInput, AepCommandResponseExpectation<AepProblemDetails>>> {
  const vector = await loadTestVector<TInput, AepCommandResponseExpectation<unknown>>(relativePath);

  return {
    ...vector,
    expected: {
      ...vector.expected,
      body: parseProblemDetails(vector.expected.body)
    }
  };
}
