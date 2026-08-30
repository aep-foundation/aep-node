import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

import {
  parseBuiltInGrantResponse,
  parseAepClaimValues,
  parseEnrollRequest,
  parseEnrollResponse,
  parseGrantRequest,
  parseInspectDocument,
  parseProblemDetails,
  parseRevokeRequest,
  parseRevokeResponse,
  parseStatusResponse,
  validateBuiltInGrantResponse,
  validateAepClaimValues,
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
  AepClaimName,
  AepClaimValues,
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
export const exampleArtifactsRoot = path.join(specArtifactsRoot, "examples");
export const registryArtifactsRoot = path.join(specArtifactsRoot, "registry");
export const testVectorArtifactsRoot = path.join(specArtifactsRoot, "test-vectors");
export const specArtifactManifestPath = path.join(specArtifactsRoot, "manifest.json");

export interface SpecArtifactManifest {
  source: string;
  source_repository: string;
  source_revision: string;
  source_directory: string;
  artifact_revision: string;
  generated_by: string;
  artifacts: {
    examples: string[];
    registry: string[];
    schemas: string[];
    "test-vectors": string[];
  };
}

export type AepConformanceRole = "agent" | "platform" | "service";
export type AepConformanceExpectation = "optional" | "required" | "unsupported";

export interface AepTestVectorApplicability {
  expectation: AepConformanceExpectation;
  profile?: string;
}

export interface AepTestVector<TInput = unknown, TExpected = unknown> {
  id: string;
  title?: string;
  description?: string;
  drafts?: string[];
  category?: string;
  applicability: Record<AepConformanceRole, AepTestVectorApplicability>;
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

export function exampleArtifactPath(relativePath: string): string {
  return path.join(exampleArtifactsRoot, relativePath);
}

export function registryArtifactPath(relativePath: string): string {
  return path.join(registryArtifactsRoot, relativePath);
}

export async function loadExampleArtifact(relativePath: string): Promise<string> {
  return readFile(exampleArtifactPath(relativePath), "utf8");
}

export async function loadRegistryArtifact<T = unknown>(relativePath: string): Promise<T> {
  return readJson<T>(registryArtifactPath(relativePath));
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

export function validateClaimValuesConformance(value: unknown): ValidationResult<AepClaimValues> {
  return validateAepClaimValues(value);
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

export function assertClaimValuesConformance(value: unknown): AepClaimValues {
  const result = validateAepClaimValues(value);

  if (!result.ok) {
    throw new AepConformanceError("Claim values failed AEP conformance validation.", result.issues);
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

export async function loadClaimValuesTestVector(): Promise<
  AepTestVector<Record<string, never>, AepClaimValues>
> {
  const vector = await loadTestVector<Record<string, never>, unknown>(
    "claims/person-contact-catalog.json"
  );

  return {
    ...vector,
    expected: parseAepClaimValues(vector.expected)
  };
}

export type AepClaimValueValidationVectorId =
  | "forward-compatible-address"
  | "invalid-address"
  | "invalid-birthdate"
  | "invalid-country-shape"
  | "invalid-email-domain"
  | "invalid-email-dot-string"
  | "invalid-email-format"
  | "invalid-empty-email"
  | "invalid-mobile"
  | "invalid-value-type"
  | "minimal-email"
  | "quoted-email";

export interface AepClaimValueValidationExpectation {
  valid: boolean;
  unknown_object_members?: "ignore";
}

export async function loadClaimValueValidationTestVector(
  id: AepClaimValueValidationVectorId
): Promise<AepTestVector<{ claim_values: unknown }, AepClaimValueValidationExpectation>> {
  return loadTestVector<{ claim_values: unknown }, AepClaimValueValidationExpectation>(
    `claims/${id}.json`
  );
}

export function loadClaimNegotiationCompatibilityTestVector(): Promise<
  AepTestVector<
    {
      inspect: {
        optional: AepClaimName[];
        preferred: AepClaimName[];
        required: AepClaimName[];
      };
      submitted: AepClaimValues;
    },
    {
      enrollment_requirement_satisfied: boolean;
      omitted_preferred_allowed: boolean;
      unknown_optional_action: "ignore";
      unknown_preferred_action: "ignore";
      unknown_submitted_default_action: "ignore";
    }
  >
> {
  return loadTestVector("claims/negotiation-compatibility.json");
}

export function loadUnknownRequiredClaimTestVector(): Promise<
  AepTestVector<{ required: AepClaimName[]; understood: AepClaimName[] }, { can_satisfy: boolean }>
> {
  return loadTestVector("claims/unknown-required-claim.json");
}

export async function loadClaimsCatalogInspectTestVector(): Promise<
  AepTestVector<Record<string, never>, InspectDocument>
> {
  const vector = await loadTestVector<Record<string, never>, unknown>(
    "inspect/claims-catalog-advertisement.json"
  );

  return {
    ...vector,
    expected: parseInspectDocument(vector.expected)
  };
}

export async function loadClaimsCatalogEnrollRequestTestVector(): Promise<
  AepTestVector<EnrollRequest, Record<string, unknown>>
> {
  const vector = await loadTestVector<unknown, Record<string, unknown>>(
    "enroll/request-claims-catalog.json"
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

export async function loadTargetedOAuthBearerRevokeRequestTestVector(): Promise<
  AepTestVector<RevokeRequest, AepCommandRequestExpectation<RevokeRequest>>
> {
  const vector = await loadTestVector<unknown, AepCommandRequestExpectation<unknown>>(
    "grant-revoke/revoke-request-targeted-oauth-bearer.json"
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

export function loadCommandIdempotencyHeaderTestVector(): Promise<
  AepTestVector<AepCommandIdempotencyHeaderInput, AepCommandIdempotencyHeaderExpectation>
> {
  return loadTestVector<AepCommandIdempotencyHeaderInput, AepCommandIdempotencyHeaderExpectation>(
    "idempotency/command-header.json"
  );
}

export function loadCommandReplayConflictTestVector(): Promise<
  AepTestVector<AepCommandReplayConflictInput, AepCommandReplayConflictExpectation>
> {
  return loadTestVector<AepCommandReplayConflictInput, AepCommandReplayConflictExpectation>(
    "idempotency/command-replay-conflict.json"
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

export interface AepCommandIdempotencyHeaderInput {
  commands: Array<"enroll" | "grant" | "revoke">;
  idempotency_key: string;
}

export interface AepCommandIdempotencyHeaderExpectation {
  enroll_body_key: "optional";
  header_required: true;
  mismatched_enroll_body_status: number;
  missing_or_empty_code: string;
  missing_or_empty_status: number;
}

export interface AepCommandReplayConflictInput {
  agent_did: string;
  first_body_hash: string;
  first_command: "enroll" | "grant" | "revoke";
  idempotency_key: string;
  second_body_hash: string;
  second_command: "enroll" | "grant" | "revoke";
}

export interface AepCommandReplayConflictExpectation {
  changed_body: {
    code: string;
    status: number;
  };
  changed_command: {
    code: string;
    status: number;
  };
  exact_retry: "cached_or_equivalent_success";
  retention_seconds_minimum: number;
  scope: ["agent_did", "idempotency_key"];
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
