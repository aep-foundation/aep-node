import { AepValidationError } from "./errors.js";
import {
  AEP_CLAIM_NAME_CONTACT_ADDRESS_PRIMARY,
  AEP_CLAIM_NAME_CONTACT_EMAIL,
  AEP_CLAIM_NAME_CONTACT_MOBILE,
  AEP_CLAIM_NAME_PERSON_BIRTHDATE,
  AEP_CLAIM_NAME_PERSON_FIRST_NAME,
  AEP_CLAIM_NAME_PERSON_LAST_NAME,
  AEP_CLAIM_NAME_PERSON_USERNAME
} from "./constants.js";
import type {
  AepClaimName,
  AepClaimValues,
  AepInspectClaims,
  ValidationIssue,
  ValidationResult
} from "./types.js";

const E164_PATTERN = /^\+[1-9][0-9]{1,14}$/;
const FULL_DATE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
const COUNTRY_PATTERN = /^[A-Z]{2}$/;
const ATEXT_PATTERN = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+$/;
const DOMAIN_LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;
const HEX_GROUP_PATTERN = /^[0-9A-Fa-f]{1,4}$/;

export function validateAepClaimValues(value: unknown): ValidationResult<AepClaimValues> {
  if (!isRecord(value)) {
    return {
      ok: false,
      issues: [{ path: "$", message: "Expected an object." }]
    };
  }

  const issues: ValidationIssue[] = [];
  optionalAddress(
    value[AEP_CLAIM_NAME_CONTACT_ADDRESS_PRIMARY],
    `$.${AEP_CLAIM_NAME_CONTACT_ADDRESS_PRIMARY}`,
    issues
  );
  optionalString(value[AEP_CLAIM_NAME_CONTACT_EMAIL], `$.${AEP_CLAIM_NAME_CONTACT_EMAIL}`, issues, {
    minLength: 3,
    format: "email"
  });
  optionalString(
    value[AEP_CLAIM_NAME_CONTACT_MOBILE],
    `$.${AEP_CLAIM_NAME_CONTACT_MOBILE}`,
    issues,
    { pattern: E164_PATTERN }
  );
  optionalString(
    value[AEP_CLAIM_NAME_PERSON_BIRTHDATE],
    `$.${AEP_CLAIM_NAME_PERSON_BIRTHDATE}`,
    issues,
    { format: "full-date", pattern: FULL_DATE_PATTERN }
  );
  optionalString(
    value[AEP_CLAIM_NAME_PERSON_FIRST_NAME],
    `$.${AEP_CLAIM_NAME_PERSON_FIRST_NAME}`,
    issues,
    { minLength: 1 }
  );
  optionalString(
    value[AEP_CLAIM_NAME_PERSON_LAST_NAME],
    `$.${AEP_CLAIM_NAME_PERSON_LAST_NAME}`,
    issues,
    { minLength: 1 }
  );
  optionalString(
    value[AEP_CLAIM_NAME_PERSON_USERNAME],
    `$.${AEP_CLAIM_NAME_PERSON_USERNAME}`,
    issues,
    { minLength: 1 }
  );

  if (issues.length > 0) {
    return { ok: false, issues };
  }

  return { ok: true, value, issues: [] };
}

export function isAepClaimValues(value: unknown): value is AepClaimValues {
  return validateAepClaimValues(value).ok;
}

export function parseAepClaimValues(value: unknown): AepClaimValues {
  const result = validateAepClaimValues(value);

  if (result.ok) {
    return result.value;
  }

  throw new AepValidationError("Invalid AEP claim values.", result.issues);
}

export interface AepClaimSupportEvaluation {
  canSatisfyRequired: boolean;
  supportedOptional: AepClaimName[];
  supportedPreferred: AepClaimName[];
  unsupportedRequired: AepClaimName[];
}

export function evaluateAepClaimSupport(
  requested: AepInspectClaims | undefined,
  supportedClaimNames: Iterable<string>
): AepClaimSupportEvaluation {
  const supported = new Set(supportedClaimNames);
  const unsupportedRequired = (requested?.required ?? []).filter(
    (claimName) => !supported.has(claimName)
  );

  return {
    canSatisfyRequired: unsupportedRequired.length === 0,
    supportedOptional: (requested?.optional ?? []).filter((claimName) => supported.has(claimName)),
    supportedPreferred: (requested?.preferred ?? []).filter((claimName) =>
      supported.has(claimName)
    ),
    unsupportedRequired
  };
}

export function missingAepRequiredClaimNames(
  requiredClaimNames: readonly AepClaimName[],
  claimValues: AepClaimValues | undefined
): AepClaimName[] {
  return requiredClaimNames.filter(
    (claimName) =>
      claimValues === undefined ||
      !Object.hasOwn(claimValues, claimName) ||
      claimValues[claimName] === undefined
  );
}

interface StringOptions {
  format?: "email" | "full-date";
  minLength?: number;
  pattern?: RegExp;
}

function optionalAddress(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (value === undefined) return;
  if (!isRecord(value)) {
    issues.push({ path, message: "Expected an object." });
    return;
  }

  requireString(value, "line1", `${path}.line1`, issues, { minLength: 1 });
  optionalString(value["line2"], `${path}.line2`, issues);
  requireString(value, "city", `${path}.city`, issues, { minLength: 1 });
  optionalString(value["region"], `${path}.region`, issues);
  optionalString(value["postal_code"], `${path}.postal_code`, issues);
  requireString(value, "country", `${path}.country`, issues, { pattern: COUNTRY_PATTERN });
}

function requireString(
  record: Record<string, unknown>,
  field: string,
  path: string,
  issues: ValidationIssue[],
  options: StringOptions = {}
): void {
  validateString(record[field], path, issues, options);
}

function optionalString(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
  options: StringOptions = {}
): void {
  if (value === undefined) return;
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

  if (options.pattern !== undefined && !options.pattern.test(value)) {
    issues.push({ path, message: `Expected string to match ${options.pattern.source}.` });
  }

  if (options.format === "email" && !isEmailMailbox(value)) {
    issues.push({ path, message: "Expected an RFC 5321 Mailbox." });
  }

  if (options.format === "full-date" && !isFullDate(value)) {
    issues.push({ path, message: "Expected an RFC 3339 full-date." });
  }
}

function isEmailMailbox(value: string): boolean {
  const separator = mailboxSeparator(value);
  if (separator < 1 || separator === value.length - 1) return false;

  const localPart = value.slice(0, separator);
  const domain = value.slice(separator + 1);
  return (
    encodedLength(localPart) <= 64 &&
    encodedLength(domain) <= 255 &&
    isLocalPart(localPart) &&
    isMailboxDomain(domain)
  );
}

function mailboxSeparator(value: string): number {
  if (!value.startsWith('"')) {
    const separator = value.indexOf("@");
    return separator === value.lastIndexOf("@") ? separator : -1;
  }

  let escaped = false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      return value[index + 1] === "@" ? index + 1 : -1;
    }
  }
  return -1;
}

function isLocalPart(value: string): boolean {
  if (value.startsWith('"')) return isQuotedLocalPart(value);
  return value.split(".").every((atom) => ATEXT_PATTERN.test(atom));
}

function isQuotedLocalPart(value: string): boolean {
  if (value.length < 2 || !value.endsWith('"')) return false;

  for (let index = 1; index < value.length - 1; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 92) {
      index += 1;
      if (index >= value.length - 1) return false;
      const escapedCode = value.charCodeAt(index);
      if (escapedCode < 32 || escapedCode > 126) return false;
      continue;
    }
    if (!((code >= 32 && code <= 33) || (code >= 35 && code <= 91) || (code >= 93 && code <= 126)))
      return false;
  }
  return true;
}

function isMailboxDomain(value: string): boolean {
  if (value.startsWith("[") || value.endsWith("]")) return isAddressLiteral(value);
  return value.split(".").every((label) => label.length <= 63 && DOMAIN_LABEL_PATTERN.test(label));
}

function isAddressLiteral(value: string): boolean {
  if (!value.startsWith("[") || !value.endsWith("]")) return false;
  const content = value.slice(1, -1);

  if (isIpv4Address(content)) return true;
  if (content.startsWith("IPv6:")) return isIpv6Address(content.slice(5));

  const separator = content.indexOf(":");
  if (separator < 1 || separator === content.length - 1) return false;
  const tag = content.slice(0, separator);
  const literal = content.slice(separator + 1);
  return (
    /^[A-Za-z0-9-]*[A-Za-z0-9]$/.test(tag) &&
    [...literal].every((character) => {
      const code = character.charCodeAt(0);
      return (code >= 33 && code <= 90) || (code >= 94 && code <= 126);
    })
  );
}

function isIpv4Address(value: string): boolean {
  const octets = value.split(".");
  return (
    octets.length === 4 &&
    octets.every((octet) => /^[0-9]{1,3}$/.test(octet) && Number(octet) <= 255)
  );
}

function isIpv6Address(value: string): boolean {
  if (value.length === 0 || value.indexOf("::") !== value.lastIndexOf("::")) return false;

  const compressed = value.includes("::");
  const sections = compressed ? value.split("::") : [value];
  if (sections.length > 2) return false;

  const left = ipv6Groups(sections[0] ?? "");
  const right = ipv6Groups(sections[1] ?? "");
  if (left === undefined || right === undefined) return false;

  const groupCount = left + right;
  return compressed ? groupCount < 8 : groupCount === 8;
}

function ipv6Groups(value: string): number | undefined {
  if (value.length === 0) return 0;
  const groups = value.split(":");
  let count = 0;

  for (let index = 0; index < groups.length; index += 1) {
    const group = groups[index] ?? "";
    if (group.includes(".")) {
      if (index !== groups.length - 1 || !isIpv4Address(group)) return undefined;
      count += 2;
    } else {
      if (!HEX_GROUP_PATTERN.test(group)) return undefined;
      count += 1;
    }
  }
  return count;
}

function encodedLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isFullDate(value: string): boolean {
  const match = FULL_DATE_PATTERN.exec(value);
  if (match === null) return false;

  const [year, month, day] = value.split("-").map(Number);
  if (year === undefined || month === undefined || day === undefined) return false;
  if (month < 1 || month > 12 || day < 1) return false;

  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= (daysInMonth[month - 1] ?? 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
