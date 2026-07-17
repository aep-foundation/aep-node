import { AEP_BINDINGS, AEP_COMMANDS } from "./constants.js";
import { AepValidationError } from "./errors.js";
import type { InspectDocument, ValidationIssue, ValidationResult } from "./types.js";

const VERSION_PATTERN = /^[0-9]+\.[0-9]+$/;
const ENDPOINT_BASE_PATTERN = /^\//;
const DID_PATTERN = /^did:/;
const IDENTITY_METHOD_PATTERN = /^[a-z0-9]+(?::[a-z0-9]+)*(?:-[a-z0-9]+)*$/;
const AUTHENTICATION_METHOD_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const COMMANDS = new Set<string>(AEP_COMMANDS);
const BINDINGS = new Set<string>(AEP_BINDINGS);

export function validateInspectDocument(value: unknown): ValidationResult<InspectDocument> {
  const issues: ValidationIssue[] = [];

  if (!isRecord(value)) {
    return {
      ok: false,
      issues: [{ path: "$", message: "Expected an object." }]
    };
  }

  requireString(value, "aep_version", issues, VERSION_PATTERN);
  validateAuthentication(value["authentication"], issues);
  validateBindings(value["bindings"], issues);
  validateClaims(value["claims"], issues);
  validateCommands(value["commands"], issues);
  validateCore(value["core"], issues);
  validateExtensions(value["extensions"], issues);
  validateHttp(value["http"], issues);
  validateIdentity(value["identity"], issues);
  validateService(value["service"], issues);

  if (issues.length > 0) {
    return { ok: false, issues };
  }

  return { ok: true, value: value as InspectDocument, issues: [] };
}

function validateAuthentication(value: unknown, issues: ValidationIssue[]): void {
  if (value === undefined) return;
  if (!requireRecord(value, "authentication", issues)) return;
  requireStringArray(value["methods"], "$.authentication.methods", issues, {
    minItems: 1,
    itemPattern: AUTHENTICATION_METHOD_PATTERN,
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
    allowedValues: BINDINGS
  });
}

function validateClaims(value: unknown, issues: ValidationIssue[]): void {
  if (value === undefined) {
    return;
  }

  if (!requireRecord(value, "claims", issues)) {
    return;
  }

  optionalStringArray(value["required"], "$.claims.required", issues);
  optionalStringArray(value["preferred"], "$.claims.preferred", issues);
  optionalStringArray(value["optional"], "$.claims.optional", issues);
}

function validateCommands(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "commands", issues)) {
    return;
  }

  requireStringArray(value["supported"], "$.commands.supported", issues, {
    minItems: 1,
    allowedValues: COMMANDS
  });
  optionalStringArray(value["grant_types"], "$.commands.grant_types", issues);
}

function validateCore(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "core", issues)) {
    return;
  }

  if (value["signing_algorithms"] !== undefined) {
    requireStringArray(value["signing_algorithms"], "$.core.signing_algorithms", issues, {
      minItems: 1
    });
  }
}

function validateExtensions(value: unknown, issues: ValidationIssue[]): void {
  if (value === undefined) {
    return;
  }

  if (!requireRecord(value, "extensions", issues)) {
    return;
  }

  optionalStringArray(value["supported"], "$.extensions.supported", issues);
}

function validateHttp(value: unknown, issues: ValidationIssue[]): void {
  if (!requireRecord(value, "http", issues)) {
    return;
  }

  requireString(value, "endpoint_base", issues, ENDPOINT_BASE_PATTERN, "$.http.endpoint_base");
  const openapi = value["openapi"];
  if (openapi === undefined) return;
  if (!requireRecord(openapi, "http.openapi", issues)) return;
  requireString(openapi, "url", issues, undefined, "$.http.openapi.url");
  if (openapi["url"] === "")
    issues.push({ path: "$.http.openapi.url", message: "Expected a non-empty string." });
  const pathMatching = openapi["path_matching"];
  if (!requireRecord(pathMatching, "http.openapi.path_matching", issues)) return;
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
    minItems: 1,
    itemPattern: IDENTITY_METHOD_PATTERN
  });
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
  allowedValues?: ReadonlySet<string>;
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
  if (options.uniqueItems && new Set(value).size !== value.length) {
    issues.push({ path, message: "Expected unique items." });
  }

  value.forEach((item, index) => {
    const itemPath = `${path}[${index}]`;

    if (typeof item !== "string") {
      issues.push({ path: itemPath, message: "Expected a string." });
      return;
    }

    if (options.allowedValues && !options.allowedValues.has(item)) {
      issues.push({ path: itemPath, message: "Expected a registered AEP value." });
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
