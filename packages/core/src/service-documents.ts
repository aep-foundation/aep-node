import { AepValidationError } from "./errors.js";
import type { ValidationIssue, ValidationResult } from "./types.js";

export const AEP_SERVICE_DOCUMENTS_EXTENSION =
  "urn:aep:ext:aep-foundation:service-documents#v=1.0.0";

export const AEP_SERVICE_DOCUMENT_TYPES = [
  "acceptable_use_policy",
  "age_or_parental_consent",
  "ai_data_use_policy",
  "community_guidelines",
  "cookie_policy",
  "data_processing_agreement",
  "data_retention_notice",
  "electronic_signature_consent",
  "privacy_policy",
  "security_policy",
  "subscription_terms",
  "supplemental_terms",
  "terms_of_service"
] as const;

export interface AepServiceDocument {
  id: string;
  type: (typeof AEP_SERVICE_DOCUMENT_TYPES)[number] | (string & Record<never, never>);
  title: string;
  enrollment: "required" | "not-required";
  representations: { media_type: string; url: string; [key: string]: unknown }[];
  [key: string]: unknown;
}

export type AepDocumentBlock =
  | { type: "paragraph"; text: string; [key: string]: unknown }
  | { type: "section"; title: string; blocks: AepDocumentBlock[]; [key: string]: unknown }
  | { type: "bulleted_list" | "numbered_list"; items: string[]; [key: string]: unknown };

export interface AepPortableDocument {
  format: "aep-service-document";
  version: "1.0";
  id: string;
  summary?: AepDocumentBlock[];
  content: AepDocumentBlock[];
  [key: string]: unknown;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}(?![\s\S])/u;
const TYPE = /^[a-z][a-z0-9_]{0,63}(?![\s\S])/u;
const MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?![\s\S])/u;

export function validateAepDocumentIds(value: unknown): ValidationResult<string[]> {
  const issues: ValidationIssue[] = [];
  if (!Array.isArray(value) || value.length > 7) {
    issues.push({ path: "$", message: "Expected at most seven document IDs." });
  } else {
    value.forEach((id, index) => {
      if (!validId(id)) issues.push({ path: `$[${index}]`, message: "Invalid document ID." });
    });
    if (new Set(value).size !== value.length)
      issues.push({ path: "$", message: "Document IDs must be unique." });
  }
  return checked<string[]>(value, issues);
}

export function parseAepDocumentIds(value: unknown): string[] {
  return parsed(validateAepDocumentIds(value), "Invalid AEP document IDs.");
}

export function validateAepServiceDocuments(
  value: unknown
): ValidationResult<AepServiceDocument[]> {
  const issues: ValidationIssue[] = [];
  if (!Array.isArray(value) || value.length === 0 || value.length > 7)
    return { ok: false, issues: [{ path: "$", message: "Expected one to seven documents." }] };
  const ids = new Set<string>();
  value.forEach((item, index) => {
    const path = `$[${index}]`;
    if (!record(item)) {
      issues.push({ path, message: "Expected a document descriptor." });
      return;
    }
    if (!validId(item["id"])) issues.push({ path: `${path}.id`, message: "Invalid document ID." });
    else if (ids.has(item["id"]))
      issues.push({ path: `${path}.id`, message: "Document IDs must be unique." });
    else ids.add(item["id"]);
    if (typeof item["type"] !== "string" || !TYPE.test(item["type"]))
      issues.push({ path: `${path}.type`, message: "Invalid document type." });
    if (!text(item["title"], 256))
      issues.push({ path: `${path}.title`, message: "Invalid document title." });
    if (item["enrollment"] !== "required" && item["enrollment"] !== "not-required")
      issues.push({ path: `${path}.enrollment`, message: "Expected required or not-required." });
    const representations = item["representations"];
    if (
      !Array.isArray(representations) ||
      representations.length < 1 ||
      representations.length > 8
    ) {
      issues.push({
        path: `${path}.representations`,
        message: "Expected one to eight representations."
      });
      return;
    }
    const mediaTypes = new Set<string>();
    representations.forEach((representation, repIndex) => {
      const repPath = `${path}.representations[${repIndex}]`;
      if (!record(representation)) {
        issues.push({ path: repPath, message: "Expected a representation." });
        return;
      }
      const mediaType = representation["media_type"];
      if (typeof mediaType !== "string" || !MEDIA_TYPE.test(mediaType) || mediaTypes.has(mediaType))
        issues.push({
          path: `${repPath}.media_type`,
          message: "Expected a unique lowercase media type without parameters."
        });
      else mediaTypes.add(mediaType);
      if (!documentUrl(representation["url"]))
        issues.push({
          path: `${repPath}.url`,
          message:
            "Expected HTTPS or loopback HTTP without user information, at most 2048 ASCII characters."
        });
    });
    if (!mediaTypes.has("text/html"))
      issues.push({
        path: `${path}.representations`,
        message: "An HTML representation is required."
      });
  });
  return checked<AepServiceDocument[]>(value, issues);
}

export function parseAepServiceDocuments(value: unknown): AepServiceDocument[] {
  return parsed(validateAepServiceDocuments(value), "Invalid AEP Service Documents.");
}

export function validateAepPortableDocument(value: unknown): ValidationResult<AepPortableDocument> {
  const issues: ValidationIssue[] = [];
  if (!record(value)) return { ok: false, issues: [{ path: "$", message: "Expected an object." }] };
  if (value["format"] !== "aep-service-document" || value["version"] !== "1.0")
    issues.push({ path: "$", message: "Unsupported portable document format or version." });
  if (!validId(value["id"])) issues.push({ path: "$.id", message: "Invalid document ID." });
  const pending: { blocks: unknown; path: string; depth: number }[] = [
    { blocks: value["content"], path: "$.content", depth: 0 }
  ];
  if (value["summary"] !== undefined)
    pending.push({ blocks: value["summary"], path: "$.summary", depth: 0 });
  let count = 0;
  while (pending.length > 0) {
    const entry = pending.pop();
    if (entry === undefined) break;
    if (!Array.isArray(entry.blocks) || entry.blocks.length === 0) {
      issues.push({ path: entry.path, message: "Expected non-empty blocks." });
      continue;
    }
    count += entry.blocks.length;
    if (count > 1024) {
      issues.push({ path: "$", message: "Document exceeds 1024 blocks." });
      break;
    }
    entry.blocks.forEach((block, index) => {
      const path = `${entry.path}[${index}]`;
      if (!record(block)) {
        issues.push({ path, message: "Expected a block." });
      } else if (block["type"] === "paragraph") {
        if (!text(block["text"], 16384)) issues.push({ path, message: "Invalid paragraph text." });
      } else if (block["type"] === "section") {
        if (!text(block["title"], 256)) issues.push({ path, message: "Invalid section title." });
        if (entry.depth >= 8)
          issues.push({ path, message: "Document exceeds eight nested sections." });
        else
          pending.push({ blocks: block["blocks"], path: `${path}.blocks`, depth: entry.depth + 1 });
      } else if (block["type"] === "bulleted_list" || block["type"] === "numbered_list") {
        const items = block["items"];
        if (
          !Array.isArray(items) ||
          items.length < 1 ||
          items.length > 128 ||
          !items.every((item) => text(item, 16384))
        )
          issues.push({ path, message: "Invalid list items." });
      } else issues.push({ path, message: "Unsupported document block type." });
    });
  }
  return checked<AepPortableDocument>(value, issues);
}

export function parseAepPortableDocument(value: unknown): AepPortableDocument {
  return parsed(validateAepPortableDocument(value), "Invalid AEP portable document.");
}

function validId(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

function text(value: unknown, maximum: number): boolean {
  return typeof value === "string" && value.length > 0 && [...value].length <= maximum;
}

function documentUrl(value: unknown): boolean {
  if (
    typeof value !== "string" ||
    value.length > 2048 ||
    !/^(?:https:\/\/[^/@?#\\\s]+|http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?)(?:[/?#][^\\\s]*)?$/u.test(
      value
    ) ||
    /[^\x21-\x7e]/u.test(value)
  )
    return false;
  try {
    const url = new URL(value);
    return !url.username && !url.password;
  } catch {
    return false;
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checked<T>(value: unknown, issues: ValidationIssue[]): ValidationResult<T> {
  // Each caller validates the known fields before crossing this protocol boundary.
  return issues.length === 0 ? { ok: true, value: value as T, issues: [] } : { ok: false, issues };
}

function parsed<T>(result: ValidationResult<T>, message: string): T {
  if (!result.ok) throw new AepValidationError(message, result.issues);
  return result.value;
}
