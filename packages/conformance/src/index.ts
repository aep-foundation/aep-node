import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

/**
 * The bundled artifacts are located relative to this module rather than to the process working
 * directory, so the package resolves its own copy wherever a consumer runs it from and cannot
 * pick up a different installed version.
 */
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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
  title: string;
  description: string;
  drafts: string[];
  category: string;
  applicability: Record<AepConformanceRole, AepTestVectorApplicability>;
  input: TInput;
  expected: TExpected;
  [key: string]: unknown;
}

export const AEP_CONFORMANCE_ROLES = ["agent", "platform", "service"] as const;
export const AEP_CONFORMANCE_EXPECTATIONS = ["optional", "required", "unsupported"] as const;
export const AEP_CONFORMANCE_PROFILES = [
  "api-key",
  "basic",
  "claims",
  "core-http",
  "oauth-bearer",
  "platform-hosted-identity",
  "service-documents"
] as const;

export type AepConformanceProfile = (typeof AEP_CONFORMANCE_PROFILES)[number];

const VECTOR_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ROLES = new Set<string>(AEP_CONFORMANCE_ROLES);
const EXPECTATIONS = new Set<string>(AEP_CONFORMANCE_EXPECTATIONS);
const PROFILES = new Set<string>(AEP_CONFORMANCE_PROFILES);
const VECTOR_CATEGORIES = new Set([
  "caching",
  "claims",
  "inspect",
  "openapi",
  "client-assertion",
  "errors",
  "idempotency",
  "enroll",
  "status",
  "service-documents",
  "grant-revoke",
  "platform",
  "protected-resource",
  "credentials/oauth-bearer",
  "credentials/api-key",
  "credentials/basic"
]);
const VECTOR_DRAFTS = new Set([
  "draft-kavian-agent-enrollment-protocol-05",
  "draft-kavian-aep-claims-01",
  "draft-kavian-aep-oauth-session-credential-04",
  "draft-kavian-aep-api-key-session-credential-04",
  "draft-kavian-aep-basic-session-credential-04",
  "draft-kavian-aep-did-web-identity-method-00",
  "draft-kavian-aep-platform-hosted-identity-01",
  "draft-kavian-aep-service-documents-00"
]);

export class AepConformanceError extends Error {
  readonly issues: ValidationIssue[];

  constructor(message: string, issues: ValidationIssue[]) {
    super(message);
    this.name = "AepConformanceError";
    this.issues = issues;
  }
}

/**
 * Checks a value against the test-vector contract.
 *
 * A vector names the behavior under test, the drafts it comes from, and how each role is
 * expected to treat it. A harness dispatches on those fields, so a vector that misdeclares them
 * would silently change which cases a role is held to.
 */
export function validateTestVector(value: unknown): ValidationResult<AepTestVector> {
  if (!isRecord(value)) {
    return { ok: false, issues: [{ path: "$", message: "Expected an object." }] };
  }

  const issues: ValidationIssue[] = [];
  const id = value["id"];

  if (typeof id !== "string" || !VECTOR_ID_PATTERN.test(id)) {
    issues.push({ path: "$.id", message: "Expected a lowercase hyphenated identifier." });
  }

  for (const field of ["title", "description", "category"] as const) {
    if (typeof value[field] !== "string" || value[field].trim().length === 0) {
      issues.push({ path: `$.${field}`, message: "Expected a non-empty string." });
    }
  }

  const drafts = value["drafts"];
  if (typeof value["category"] === "string" && !VECTOR_CATEGORIES.has(value["category"])) {
    issues.push({ path: "$.category", message: "Expected a known vector category." });
  }

  if (!Array.isArray(drafts) || drafts.length === 0) {
    issues.push({ path: "$.drafts", message: "Expected a non-empty array." });
  } else {
    drafts.forEach((draft, index) => {
      if (typeof draft !== "string" || !VECTOR_DRAFTS.has(draft)) {
        issues.push({ path: `$.drafts[${index}]`, message: "Expected a draft identifier." });
      }
    });
  }

  validateApplicability(value["applicability"], issues);

  for (const field of ["input", "expected"] as const) {
    if (!isRecord(value[field])) {
      issues.push({ path: `$.${field}`, message: "Expected an object." });
    }
  }

  if (issues.length > 0) {
    return { ok: false, issues };
  }

  return { ok: true, issues: [], value: value as unknown as AepTestVector };
}

/**
 * Every role is classified exactly once. An executable classification names the profile that
 * activates the case, and an unsupported one names none, so a harness cannot dispatch a case to
 * a role the vector does not cover.
 */
function validateApplicability(value: unknown, issues: ValidationIssue[]): void {
  if (!isRecord(value)) {
    issues.push({ path: "$.applicability", message: "Expected an object." });
    return;
  }

  for (const role of Object.keys(value)) {
    if (!ROLES.has(role)) {
      issues.push({ path: `$.applicability.${role}`, message: "Expected a known role." });
    }
  }

  for (const role of AEP_CONFORMANCE_ROLES) {
    const classification = value[role];
    const rolePath = `$.applicability.${role}`;

    if (!isRecord(classification)) {
      issues.push({ path: rolePath, message: "Expected a classification for this role." });
      continue;
    }

    const expectation = classification["expectation"];
    const profile = classification["profile"];

    if (typeof expectation !== "string" || !EXPECTATIONS.has(expectation)) {
      issues.push({
        path: `${rolePath}.expectation`,
        message: "Expected required, optional, or unsupported."
      });
      continue;
    }

    if (expectation === "unsupported") {
      if (profile !== undefined) {
        issues.push({
          path: `${rolePath}.profile`,
          message: "Expected no profile for an unsupported classification."
        });
      }
      continue;
    }

    if (typeof profile !== "string" || !PROFILES.has(profile)) {
      issues.push({
        path: `${rolePath}.profile`,
        message: "Expected a known conformance profile."
      });
    }
  }
}

/** Throws unless the value satisfies the test-vector contract. */
export function assertTestVector(value: unknown): AepTestVector {
  const result = validateTestVector(value);

  if (!result.ok) {
    throw new AepConformanceError("Test vector failed AEP conformance validation.", result.issues);
  }

  return result.value;
}

export interface SpecArtifactIntegrityResult {
  ok: boolean;
  expected: string;
  actual: string;
  files: number;
}

/**
 * Recomputes the digest the sync script recorded for the bundled artifacts.
 *
 * The manifest itself is excluded, because the digest is taken before the manifest that carries
 * it is written. A mismatch means the shipped artifacts no longer match the revision the manifest
 * names, so a conformance run would be measuring against something other than the pinned specs.
 */
export async function verifySpecArtifactIntegrity(): Promise<SpecArtifactIntegrityResult> {
  const manifest = await loadSpecArtifactManifest();
  const files = (await listSpecArtifactFiles(specArtifactsRoot)).filter(
    (file) => file !== "manifest.json"
  );
  const hash = createHash("sha256");

  for (const file of files) {
    hash.update(file);
    hash.update("\0");
    hash.update(await readFile(path.join(specArtifactsRoot, file)));
    hash.update("\0");
  }

  const actual = `sha256:${hash.digest("hex")}`;

  return {
    ok: actual === manifest.artifact_revision,
    expected: manifest.artifact_revision,
    actual,
    files: files.length
  };
}

/** Throws unless the bundled artifacts still match the digest the manifest records. */
export async function assertSpecArtifactIntegrity(): Promise<SpecArtifactIntegrityResult> {
  const result = await verifySpecArtifactIntegrity();

  if (!result.ok) {
    throw new AepConformanceError("Bundled AEP spec artifacts failed integrity verification.", [
      {
        path: "$.artifact_revision",
        message: `Expected ${result.expected}, computed ${result.actual}.`
      }
    ]);
  }

  return result;
}

async function listSpecArtifactFiles(root: string): Promise<string[]> {
  const files: string[] = [];

  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile() && (entry.name.endsWith(".json") || entry.name.endsWith(".md"))) {
        files.push(path.relative(root, absolute).split(path.sep).join("/"));
      }
    }
  };

  await visit(root);
  return files.sort();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function loadSpecArtifactManifest(): Promise<SpecArtifactManifest> {
  return readJson<SpecArtifactManifest>(specArtifactManifestPath);
}

export function schemaArtifactPath(relativePath: string): string {
  return containedArtifactPath(schemaArtifactsRoot, relativePath, "schema");
}

export function exampleArtifactPath(relativePath: string): string {
  return containedArtifactPath(exampleArtifactsRoot, relativePath, "example");
}

export function registryArtifactPath(relativePath: string): string {
  return containedArtifactPath(registryArtifactsRoot, relativePath, "registry");
}

export async function loadExampleArtifact(relativePath: string): Promise<string> {
  return readFile(exampleArtifactPath(relativePath), "utf8");
}

export async function loadRegistryArtifact<T = unknown>(relativePath: string): Promise<T> {
  return readJson<T>(registryArtifactPath(relativePath));
}

export function testVectorArtifactPath(relativePath: string): string {
  return containedArtifactPath(testVectorArtifactsRoot, relativePath, "test vector");
}

/**
 * Resolves an artifact path and refuses one that leaves its root.
 *
 * Vector and schema paths are frequently taken from an index or a harness configuration, so a
 * path that traverses upwards would let that input read files the package does not ship.
 */
function containedArtifactPath(root: string, relativePath: string, label: string): string {
  const resolved = path.resolve(root, relativePath);

  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new AepConformanceError(`AEP ${label} path escapes the bundled spec artifacts.`, [
      { path: "$", message: `Expected a path inside the bundled ${label} artifacts.` }
    ]);
  }

  return resolved;
}

export async function loadSchemaArtifact<T = unknown>(relativePath: string): Promise<T> {
  return readJson<T>(schemaArtifactPath(relativePath));
}

/**
 * Loads a bundled test vector and checks it against the vector contract before returning it, so
 * a harness never dispatches on fields that were never verified.
 */
export async function loadTestVector<TInput = unknown, TExpected = unknown>(
  relativePath: string
): Promise<AepTestVector<TInput, TExpected>> {
  const vector = await readJson<unknown>(testVectorArtifactPath(relativePath));
  const validated = assertTestVector(vector);
  if (path.normalize(relativePath) !== path.join(validated.category, `${validated.id}.json`)) {
    throw new AepConformanceError("Test vector path does not match its category and identifier.", [
      {
        path: relativePath,
        message: "Expected the vector category and identifier to match its path."
      }
    ]);
  }
  return validated as unknown as AepTestVector<TInput, TExpected>;
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
  const contents = await readFile(file, "utf8");

  try {
    return JSON.parse(contents) as T;
  } catch {
    throw new AepConformanceError(`AEP spec artifact ${file} is not valid JSON.`, [
      { path: "$", message: "Expected a JSON document." }
    ]);
  }
}

export interface AepCommandRequestExpectation<TBody> {
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
