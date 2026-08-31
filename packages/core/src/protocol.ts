import {
  AEP_ASSERTION_OPERATIONS,
  AEP_GRANT_TYPE_API_KEY,
  AEP_GRANT_TYPE_BASIC,
  AEP_GRANT_TYPE_OAUTH_BEARER
} from "./constants.js";
import { validateAepClaimValues } from "./claims.js";
import { AepValidationError } from "./errors.js";
import type {
  AepBuiltInGrantResponse,
  AepClientAssertionClaims,
  AepProblemDetails,
  ApiKeyGrantResponse,
  BasicGrantResponse,
  EnrollRequest,
  EnrollResponse,
  GrantRequest,
  OAuthBearerGrantResponse,
  RevokeRequest,
  RevokeResponse,
  StatusResponse,
  ValidationIssue,
  ValidationResult
} from "./types.js";

const ASSERTION_OPERATIONS = new Set<string>(AEP_ASSERTION_OPERATIONS);
const ENROLLMENT_STATUSES = new Set<string>(["active", "pending", "rejected"]);
const AGENT_STATUSES = new Set<string>([
  "active",
  "pending",
  "rejected",
  "suspended",
  "terminated",
  "unavailable"
]);
const OWNER_ACTION_REQUIRED_VALUES = new Set<string>(["true", "false"]);

export function validateEnrollRequest(value: unknown): ValidationResult<EnrollRequest> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "agent_did", issues, { minLength: 1 });
  optionalClaimValues(value["claims"], issues);
  optionalString(value["idempotency_key"], "$.idempotency_key", issues, { minLength: 1 });
  return result(value as EnrollRequest, issues);
}

export function parseEnrollRequest(value: unknown): EnrollRequest {
  return parseWith(validateEnrollRequest(value), "Invalid AEP Enroll request.");
}

export function validateEnrollResponse(value: unknown): ValidationResult<EnrollResponse> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "status", issues, {
    allowedValues: ENROLLMENT_STATUSES
  });
  optionalString(value["owner_action_required"], "$.owner_action_required", issues, {
    allowedValues: OWNER_ACTION_REQUIRED_VALUES
  });
  optionalNonEmptyStringArray(value["verification_pending"], "$.verification_pending", issues);
  optionalNonEmptyStringArray(value["requirements_pending"], "$.requirements_pending", issues);
  return result(value as EnrollResponse, issues);
}

export function parseEnrollResponse(value: unknown): EnrollResponse {
  return parseWith(validateEnrollResponse(value), "Invalid AEP Enroll response.");
}

export function validateStatusResponse(value: unknown): ValidationResult<StatusResponse> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "status", issues, { allowedValues: AGENT_STATUSES });
  optionalString(value["owner_action_required"], "$.owner_action_required", issues, {
    allowedValues: OWNER_ACTION_REQUIRED_VALUES
  });
  optionalNonEmptyStringArray(value["verification_pending"], "$.verification_pending", issues);
  optionalNonEmptyStringArray(value["requirements_pending"], "$.requirements_pending", issues);
  optionalString(value["since"], "$.since", issues);
  return result(value as StatusResponse, issues);
}

export function parseStatusResponse(value: unknown): StatusResponse {
  return parseWith(validateStatusResponse(value), "Invalid AEP Status response.");
}

export function validateGrantRequest(value: unknown): ValidationResult<GrantRequest> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "grant_type", issues, { minLength: 1 });
  optionalStringArray(value["requested_scopes"], "$.requested_scopes", issues);
  return result(value as GrantRequest, issues);
}

export function parseGrantRequest(value: unknown): GrantRequest {
  return parseWith(validateGrantRequest(value), "Invalid AEP Grant request.");
}

export function validateRevokeRequest(value: unknown): ValidationResult<RevokeRequest> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  optionalString(value["grant_type"], "$.grant_type", issues, { minLength: 1 });
  optionalString(value["credential_id"], "$.credential_id", issues, { minLength: 1 });
  optionalString(value["all_grant_types"], "$.all_grant_types", issues, {
    allowedValues: new Set(["true"])
  });

  const hasAllGrantTypes = value["all_grant_types"] !== undefined;
  const hasCredentialId = value["credential_id"] !== undefined;
  const hasGrantType = value["grant_type"] !== undefined;

  if (!hasAllGrantTypes && !hasGrantType) {
    issues.push({
      path: "$",
      message: "Expected grant_type or all_grant_types."
    });
  }

  if (
    (hasAllGrantTypes && (hasCredentialId || hasGrantType)) ||
    (hasCredentialId && !hasGrantType)
  ) {
    issues.push({
      path: "$",
      message: "Expected grant_type, grant_type with credential_id, or all_grant_types."
    });
  }

  return result(value as RevokeRequest, issues);
}

export function parseRevokeRequest(value: unknown): RevokeRequest {
  return parseWith(validateRevokeRequest(value), "Invalid AEP Revoke request.");
}

export function validateRevokeResponse(value: unknown): ValidationResult<RevokeResponse> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  if (Object.keys(value).length > 0) {
    issues.push({ path: "$", message: "Expected an empty object." });
  }

  return result(value as RevokeResponse, issues);
}

export function parseRevokeResponse(value: unknown): RevokeResponse {
  return parseWith(validateRevokeResponse(value), "Invalid AEP Revoke response.");
}

export interface ValidateClientAssertionClaimsOptions {
  allowInsecureLoopback?: boolean;
}

export function validateClientAssertionClaims(
  value: unknown,
  options: ValidateClientAssertionClaimsOptions = {}
): ValidationResult<AepClientAssertionClaims> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "iss", issues, { minLength: 1 });
  requireString(value, "sub", issues, { minLength: 1 });
  requireString(value, "aud", issues, { minLength: 1 });
  requireString(value, "op", issues, { allowedValues: ASSERTION_OPERATIONS });
  optionalString(value["resource"], "$.resource", issues, { minLength: 1 });
  if (value["op"] === "authenticate" && value["resource"] === undefined) {
    issues.push({ path: "$.resource", message: "Expected a protected-resource URI." });
  }
  if (value["op"] !== "authenticate" && value["resource"] !== undefined) {
    issues.push({ path: "$.resource", message: "resource is only valid for authenticate." });
  }
  requireInteger(value["iat"], "$.iat", issues);
  requireInteger(value["exp"], "$.exp", issues);
  requireString(value, "jti", issues, { minLength: 1 });
  if (
    typeof value["iss"] === "string" &&
    typeof value["sub"] === "string" &&
    value["iss"] !== value["sub"]
  ) {
    issues.push({ path: "$.sub", message: "Expected the Agent DID from iss." });
  }
  if (
    typeof value["iat"] === "number" &&
    Number.isInteger(value["iat"]) &&
    typeof value["exp"] === "number" &&
    Number.isInteger(value["exp"]) &&
    (value["exp"] <= value["iat"] || value["exp"] - value["iat"] > 300)
  ) {
    issues.push({ path: "$.exp", message: "Expected a lifetime between 1 and 300 seconds." });
  }
  if (
    value["resource"] !== undefined &&
    (typeof value["resource"] !== "string" ||
      !isAllowedResourceUri(value["resource"], options.allowInsecureLoopback === true))
  ) {
    issues.push({
      path: "$.resource",
      message: "Expected an absolute HTTPS URI without a fragment."
    });
  }
  return result(value as AepClientAssertionClaims, issues);
}

export function parseClientAssertionClaims(
  value: unknown,
  options: ValidateClientAssertionClaimsOptions = {}
): AepClientAssertionClaims {
  return parseWith(
    validateClientAssertionClaims(value, options),
    "Invalid AEP client assertion claims."
  );
}

function isAllowedResourceUri(value: string, allowInsecureLoopback: boolean): boolean {
  try {
    const url = new URL(value);
    if (url.hash.length !== 0) return false;
    if (url.protocol === "https:") return true;
    return allowInsecureLoopback && url.protocol === "http:" && isLoopbackHostname(url.hostname);
  } catch {
    return false;
  }
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export function validateProblemDetails(value: unknown): ValidationResult<AepProblemDetails> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "type", issues, { minLength: 1 });
  requireString(value, "title", issues, { minLength: 1 });
  requireInteger(value["status"], "$.status", issues);
  requireString(value, "code", issues, { minLength: 1 });
  if (
    typeof value["type"] === "string" &&
    typeof value["code"] === "string" &&
    value["type"] !== `urn:aep:error:${value["code"]}`
  ) {
    issues.push({ path: "$.type", message: "Expected an AEP error URN matching code." });
  }
  optionalString(value["detail"], "$.detail", issues);
  optionalString(value["instance"], "$.instance", issues);
  optionalString(value["owner_action_required"], "$.owner_action_required", issues, {
    allowedValues: new Set(["true"])
  });
  optionalNonEmptyStringArray(value["verification_pending"], "$.verification_pending", issues);
  optionalNonEmptyStringArray(value["requirements_pending"], "$.requirements_pending", issues);
  if (
    value["code"] === "not_recognized" &&
    (value["owner_action_required"] !== undefined ||
      value["verification_pending"] !== undefined ||
      value["requirements_pending"] !== undefined)
  ) {
    issues.push({
      path: "$",
      message: "not_recognized must not expose pending or owner-action metadata."
    });
  }
  return result(value as AepProblemDetails, issues);
}

export function parseProblemDetails(value: unknown): AepProblemDetails {
  return parseWith(validateProblemDetails(value), "Invalid AEP Problem Details.");
}

export function validateOAuthBearerGrantResponse(
  value: unknown
): ValidationResult<OAuthBearerGrantResponse> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "access_token", issues, { minLength: 1 });
  requireString(value, "credential_id", issues, { minLength: 1 });
  requireString(value, "expires_at", issues, { minLength: 1 });
  requireDateTime(value["expires_at"], "$.expires_at", issues);
  optionalNullableStringArray(value["scopes"], "$.scopes", issues);
  requireString(value, "token_type", issues, { allowedValues: new Set(["Bearer"]) });
  return result(
    { ...(value as OAuthBearerGrantResponse), scopes: normalizedScopes(value["scopes"]) },
    issues
  );
}

export function validateApiKeyGrantResponse(value: unknown): ValidationResult<ApiKeyGrantResponse> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "api_key", issues, { minLength: 1 });
  requireString(value, "credential_id", issues, { minLength: 1 });
  requireString(value, "expires_at", issues, { minLength: 1 });
  requireDateTime(value["expires_at"], "$.expires_at", issues);
  requireString(value, "header", issues, { minLength: 1 });
  optionalNullableStringArray(value["scopes"], "$.scopes", issues);
  return result(
    { ...(value as ApiKeyGrantResponse), scopes: normalizedScopes(value["scopes"]) },
    issues
  );
}

export function validateBasicGrantResponse(value: unknown): ValidationResult<BasicGrantResponse> {
  if (!isRecord(value)) {
    return invalidRoot();
  }

  const issues: ValidationIssue[] = [];
  requireString(value, "credential_id", issues, { minLength: 1 });
  requireString(value, "expires_at", issues, { minLength: 1 });
  requireDateTime(value["expires_at"], "$.expires_at", issues);
  requireString(value, "password", issues, { minLength: 1 });
  optionalString(value["realm"], "$.realm", issues, { minLength: 1 });
  optionalNullableStringArray(value["scopes"], "$.scopes", issues);
  requireString(value, "username", issues, { minLength: 1 });
  return result(
    { ...(value as BasicGrantResponse), scopes: normalizedScopes(value["scopes"]) },
    issues
  );
}

export function validateBuiltInGrantResponse(
  grantType: string,
  value: unknown
): ValidationResult<AepBuiltInGrantResponse> {
  if (grantType === AEP_GRANT_TYPE_OAUTH_BEARER) {
    return validateOAuthBearerGrantResponse(value);
  }

  if (grantType === AEP_GRANT_TYPE_API_KEY) {
    return validateApiKeyGrantResponse(value);
  }

  if (grantType === AEP_GRANT_TYPE_BASIC) {
    return validateBasicGrantResponse(value);
  }

  return {
    ok: false,
    issues: [{ path: "$.grant_type", message: "Expected a built-in AEP grant type." }]
  };
}

export function parseBuiltInGrantResponse(
  grantType: string,
  value: unknown
): AepBuiltInGrantResponse {
  return parseWith(validateBuiltInGrantResponse(grantType, value), "Invalid AEP Grant response.");
}

function parseWith<T>(validation: ValidationResult<T>, message: string): T {
  if (validation.ok) {
    return validation.value;
  }

  throw new AepValidationError(message, validation.issues);
}

function invalidRoot<T>(): ValidationResult<T> {
  return {
    ok: false,
    issues: [{ path: "$", message: "Expected an object." }]
  };
}

function result<T>(value: T, issues: ValidationIssue[]): ValidationResult<T> {
  if (issues.length > 0) {
    return { ok: false, issues };
  }

  return { ok: true, issues: [], value };
}

interface StringOptions {
  allowedValues?: ReadonlySet<string>;
  minLength?: number;
  pattern?: RegExp;
}

function requireString(
  record: Record<string, unknown>,
  field: string,
  issues: ValidationIssue[],
  options: StringOptions = {}
): void {
  validateString(record[field], `$.${field}`, issues, options);
}

function optionalString(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
  options: StringOptions = {}
): void {
  if (value === undefined) {
    return;
  }

  validateString(value, path, issues, options);
}

function validateString(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
  options: StringOptions
): void {
  if (typeof value !== "string") {
    issues.push({ path, message: "Expected a string." });
    return;
  }

  if (options.minLength !== undefined && value.length < options.minLength) {
    issues.push({ path, message: `Expected at least ${options.minLength} character(s).` });
  }

  if (options.allowedValues !== undefined && !options.allowedValues.has(value)) {
    issues.push({ path, message: "Expected a registered AEP value." });
  }

  if (options.pattern !== undefined && !options.pattern.test(value)) {
    issues.push({ path, message: `Expected string to match ${options.pattern.source}.` });
  }
}

function optionalClaimValues(value: unknown, issues: ValidationIssue[]): void {
  if (value === undefined) {
    return;
  }

  const claims = validateAepClaimValues(value);
  if (!claims.ok) {
    issues.push(
      ...claims.issues.map((issue) => ({
        ...issue,
        path: issue.path === "$" ? "$.claims" : issue.path.replace(/^\$/, "$.claims")
      }))
    );
  }
}

function requireInteger(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (!Number.isInteger(value)) {
    issues.push({ path, message: "Expected an integer." });
  }
}

function requireDateTime(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (typeof value === "string" && Number.isNaN(Date.parse(value))) {
    issues.push({ path, message: "Expected a valid date-time string." });
  }
}

function optionalStringArray(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (value === undefined) {
    return;
  }

  requireStringArray(value, path, issues);
}

function optionalNullableStringArray(
  value: unknown,
  path: string,
  issues: ValidationIssue[]
): void {
  if (value === undefined || value === null) {
    return;
  }

  requireStringArray(value, path, issues);
}

function normalizedScopes(value: unknown): string[] {
  return Array.isArray(value) && value.every((scope) => typeof scope === "string")
    ? [...value]
    : [];
}

function optionalNonEmptyStringArray(
  value: unknown,
  path: string,
  issues: ValidationIssue[]
): void {
  if (value === undefined) return;
  requireStringArray(value, path, issues);
  if (Array.isArray(value) && value.length === 0) {
    issues.push({ path, message: "Expected at least 1 item(s)." });
  }
}

function requireStringArray(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (!Array.isArray(value)) {
    issues.push({ path, message: "Expected an array." });
    return;
  }

  value.forEach((item, index) => {
    if (typeof item !== "string") {
      issues.push({ path: `${path}[${index}]`, message: "Expected a string." });
    }
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
