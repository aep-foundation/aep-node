import {
  AEP_AUTHENTICATED_COMMANDS,
  AEP_BINDINGS,
  AEP_SIGNING_ALGORITHMS,
  AEP_VERSION
} from "./constants.js";
import { AepValidationError } from "./errors.js";
import type { InspectDocument, ValidationIssue, ValidationResult } from "./types.js";

const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const ENDPOINT_BASE_PATTERN = /^\//;
const DID_PATTERN = /^did:/;
const IDENTITY_METHOD_PATTERN = /^[a-z0-9]+(?::[a-z0-9]+)*(?:-[a-z0-9]+)*$/;
const ADVERTISEMENT_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const CLAIM_NAME_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$/;

const AUTHENTICATED_COMMANDS = new Set<string>(AEP_AUTHENTICATED_COMMANDS);

export function validateInspectDocument(value: unknown): ValidationResult<InspectDocument> {
  const issues: ValidationIssue[] = [];

  if (!isRecord(value)) {
    return {
      ok: false,
      issues: [{ path: "$", message: "Expected an object." }]
    };
  }

  validateVersion(value["aep_version"], issues);
  validateAuthentication(value["authentication"], issues);
  validateBindings(value["bindings"], issues);
  validateClaims(value["claims"], issues);
  validateCommands(value["commands"], issues);
  validateCore(value["core"], issues);
  validateExtensions(value["extensions"], issues);
  validateHttp(value["http"], issues);
  validateIdentity(value["identity"], issues);
  validateCommandIdentityRelationship(value, issues);
  validateService(value["service"], issues);

  if (issues.length > 0) {
    return { ok: false, issues };
  }

  return { ok: true, value: value as InspectDocument, issues: [] };
}

function validateAuthentication(value: unknown, issues: ValidationIssue[]): void {
  if (value === undefined) return;
  if (!requireRecord(value, "authentication", issues)) return;
  rejectUnknownProperties(value, ["methods"], "$.authentication", issues);
  requireStringArray(value["methods"], "$.authentication.methods", issues, {
    minItems: 1,
    maxItems: 16,
    itemPattern: ADVERTISEMENT_PATTERN,
    uniqueItems: true
  });
}

export function isInspectDocument(value: unknown): value is InspectDocument {
  return validateInspectDocument(value).ok;
}

export function parseInspectDocument(value: unknown): InspectDocument {
  const result = validateInspectDocument(value);

  if (result.ok) {
    return result.value;
  }

  throw new AepValidationError("Invalid AEP Inspect document.", result.issues);
}

function validateBindings(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "bindings", issues)) {
    return;
  }

  requireStringArray(value["supported"], "$.bindings.supported", issues, {
    minItems: 1,
    itemPattern: ADVERTISEMENT_PATTERN
  });
  if (Array.isArray(value["supported"]) && !value["supported"].includes(AEP_BINDINGS[0])) {
    issues.push({ path: "$.bindings.supported", message: "Expected http to be advertised." });
  }
}

function validateClaims(value: unknown, issues: ValidationIssue[]): void {
  if (value === undefined) {
    return;
  }

  if (!requireRecord(value, "claims", issues)) {
    return;
  }

  optionalStringArray(value["required"], "$.claims.required", issues, {
    itemPattern: CLAIM_NAME_PATTERN
  });
  optionalStringArray(value["preferred"], "$.claims.preferred", issues, {
    itemPattern: CLAIM_NAME_PATTERN
  });
  optionalStringArray(value["optional"], "$.claims.optional", issues, {
    itemPattern: CLAIM_NAME_PATTERN
  });
}

function validateCommands(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "commands", issues)) {
    return;
  }

  const supported = value["supported"];
  requireStringArray(supported, "$.commands.supported", issues, {
    minItems: 1,
    itemPattern: ADVERTISEMENT_PATTERN
  });
  if (Array.isArray(supported) && !supported.includes("inspect")) {
    issues.push({ path: "$.commands.supported", message: "Expected inspect to be advertised." });
  }
  const grantTypes = value["grant_types"];
  optionalStringArray(grantTypes, "$.commands.grant_types", issues, {
    itemPattern: ADVERTISEMENT_PATTERN
  });
  if (
    Array.isArray(supported) &&
    supported.some((command) => command === "grant" || command === "revoke") &&
    (!Array.isArray(grantTypes) || grantTypes.length === 0)
  ) {
    issues.push({
      path: "$.commands.grant_types",
      message: "Expected at least one grant type when Grant or Revoke is advertised."
    });
  }
}

export function isAepVersionCompatible(received: string, supported = AEP_VERSION): boolean {
  const receivedVersion = parseVersion(received);
  const supportedVersion = parseVersion(supported);
  return receivedVersion !== undefined && receivedVersion.major === supportedVersion?.major;
}

function validateVersion(value: unknown, issues: ValidationIssue[]): void {
  if (typeof value !== "string") {
    issues.push({ path: "$.aep_version", message: "Expected a string." });
    return;
  }
  if (!VERSION_PATTERN.test(value)) {
    issues.push({
      path: "$.aep_version",
      message: `Expected string to match ${VERSION_PATTERN.source}.`
    });
    return;
  }
  if (!isAepVersionCompatible(value)) {
    issues.push({ path: "$.aep_version", message: `Unsupported AEP major version: ${value}.` });
  }
}

function parseVersion(value: string): { major: string; minor: string } | undefined {
  if (!VERSION_PATTERN.test(value)) return undefined;
  const [major, minor] = value.split(".");
  return major === undefined || minor === undefined ? undefined : { major, minor };
}

function validateCore(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "core", issues)) {
    return;
  }

  const algorithms = value["signing_algorithms"];
  requireStringArray(algorithms, "$.core.signing_algorithms", issues, { minItems: 1 });
  if (Array.isArray(algorithms)) {
    for (const algorithm of AEP_SIGNING_ALGORITHMS) {
      if (!algorithms.includes(algorithm)) {
        issues.push({
          path: "$.core.signing_algorithms",
          message: `Expected ${algorithm} to be advertised.`
        });
      }
    }
  }
}

function validateExtensions(value: unknown, issues: ValidationIssue[]): void {
  if (value === undefined) {
    return;
  }

  if (!requireRecord(value, "extensions", issues)) {
    return;
  }

  const supported = value["supported"];
  optionalStringArray(supported, "$.extensions.supported", issues);
  if (Array.isArray(supported)) {
    supported.forEach((extension, index) => {
      if (typeof extension === "string" && !isAbsoluteUri(extension)) {
        issues.push({
          path: `$.extensions.supported[${index}]`,
          message: "Expected an absolute URI."
        });
      }
    });
  }
}

function validateHttp(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "http", issues)) {
    return;
  }

  if (value["endpoint_base"] !== undefined) {
    requireString(value, "endpoint_base", issues, ENDPOINT_BASE_PATTERN, "$.http.endpoint_base");
  }
  const openapi = value["openapi"];
  if (openapi === undefined) return;
  if (!requireRecord(openapi, "http.openapi", issues)) return;
  rejectUnknownProperties(openapi, ["path_matching", "url"], "$.http.openapi", issues);
  requireString(openapi, "url", issues, undefined, "$.http.openapi.url");
  if (openapi["url"] === "")
    issues.push({ path: "$.http.openapi.url", message: "Expected a non-empty string." });
  else if (typeof openapi["url"] === "string" && !isUriReference(openapi["url"]))
    issues.push({ path: "$.http.openapi.url", message: "Expected a URI reference." });
  const pathMatching = openapi["path_matching"];
  if (!requireRecord(pathMatching, "http.openapi.path_matching", issues)) return;
  rejectUnknownProperties(pathMatching, ["trailing_slash"], "$.http.openapi.path_matching", issues);
  const trailingSlash = pathMatching["trailing_slash"];
  if (trailingSlash !== "strict" && trailingSlash !== "equivalent")
    issues.push({
      path: "$.http.openapi.path_matching.trailing_slash",
      message: "Expected strict or equivalent."
    });
}

function validateIdentity(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "identity", issues)) {
    return;
  }

  requireStringArray(value["methods"], "$.identity.methods", issues, {
    itemPattern: IDENTITY_METHOD_PATTERN
  });
}

function validateCommandIdentityRelationship(
  document: Record<string, unknown>,
  issues: ValidationIssue[]
): void {
  const commands = document["commands"];
  const identity = document["identity"];
  if (!isRecord(commands) || !isRecord(identity)) return;
  const supported = commands["supported"];
  const methods = identity["methods"];
  if (
    Array.isArray(supported) &&
    supported.some(
      (command) => typeof command === "string" && AUTHENTICATED_COMMANDS.has(command)
    ) &&
    Array.isArray(methods) &&
    methods.length === 0
  ) {
    issues.push({
      path: "$.identity.methods",
      message: "Expected at least one identity method for authenticated commands."
    });
  }
}

function validateService(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "service", issues)) {
    return;
  }

  requireString(value, "did", issues, DID_PATTERN, "$.service.did");
}

function requireRecord(
  value: unknown,
  field: string,
  issues: ValidationIssue[]
): value is Record<string, unknown> {
  if (!isRecord(value)) {
    issues.push({
      path: `$.${field}`,
      message: "Expected an object."
    });
    return false;
  }

  return true;
}

function requireString(
  record: Record<string, unknown>,
  field: string,
  issues: ValidationIssue[],
  pattern?: RegExp,
  path = `$.${field}`
): void {
  const value = record[field];

  if (typeof value !== "string") {
    issues.push({ path, message: "Expected a string." });
    return;
  }

  if (pattern && !pattern.test(value)) {
    issues.push({ path, message: `Expected string to match ${pattern.source}.` });
  }
}

function optionalStringArray(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
  options: StringArrayOptions = {}
): void {
  if (value === undefined) {
    return;
  }

  requireStringArray(value, path, issues, options);
}

interface StringArrayOptions {
  minItems?: number;
  maxItems?: number;
  itemPattern?: RegExp;
  uniqueItems?: boolean;
}

function requireStringArray(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
  options: StringArrayOptions = {}
): void {
  if (!Array.isArray(value)) {
    issues.push({ path, message: "Expected an array." });
    return;
  }

  if (options.minItems !== undefined && value.length < options.minItems) {
    issues.push({ path, message: `Expected at least ${options.minItems} item(s).` });
  }
  if (options.maxItems !== undefined && value.length > options.maxItems) {
    issues.push({ path, message: `Expected at most ${options.maxItems} item(s).` });
  }
  if (options.uniqueItems && new Set(value).size !== value.length) {
    issues.push({ path, message: "Expected unique items." });
  }

  value.forEach((item, index) => {
    const itemPath = `${path}[${index}]`;

    if (typeof item !== "string") {
      issues.push({ path: itemPath, message: "Expected a string." });
      return;
    }

    if (options.itemPattern && !options.itemPattern.test(item)) {
      issues.push({
        path: itemPath,
        message: `Expected string to match ${options.itemPattern.source}.`
      });
    }
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAbsoluteUri(value: string): boolean {
  try {
    return new URL(value).protocol.length > 1;
  } catch {
    return false;
  }
}

function isUriReference(value: string): boolean {
  try {
    new URL(value, "https://aep.invalid/");
    return !/[\u0000-\u0020<>"{}|\\^`]/u.test(value);
  } catch {
    return false;
  }
}

function rejectUnknownProperties(
  value: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
  issues: ValidationIssue[]
): void {
  const names = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!names.has(key)) {
      issues.push({ path: `${path}.${key}`, message: "Expected no additional property." });
    }
  }
}
