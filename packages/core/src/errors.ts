import type {
  AepErrorCode,
  AepExtensibleString,
  AepProblemDetails,
  ValidationIssue
} from "./types.js";

const ERROR_CODE_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;

export class AepValidationError extends Error {
  readonly issues: ValidationIssue[];

  constructor(message: string, issues: ValidationIssue[]) {
    super(message);
    this.name = "AepValidationError";
    this.issues = issues;
  }
}

export class AepAuthorizationCarrierError extends Error {
  readonly code: "invalid_request" | "not_recognized";

  constructor(message: string, code: "invalid_request" | "not_recognized") {
    super(message);
    this.name = "AepAuthorizationCarrierError";
    this.code = code;
  }
}

export class AepIdempotencyError extends Error {
  readonly code = "invalid_request";

  constructor(message: string) {
    super(message);
    this.name = "AepIdempotencyError";
  }
}

export interface CreateProblemDetailsInput {
  code: AepExtensibleString<AepErrorCode>;
  detail?: string;
  instance?: string;
  /** Names of submitted claims whose asynchronous verification has not completed. */
  verification_pending?: string[];
  /** Names of requirements the Agent still needs to satisfy. */
  requirements_pending?: string[];
  /** Serialized only when the Owner must complete an out-of-band action. */
  owner_action_required?: boolean;
  status: number;
  title: string;
}

/**
 * Builds a Problem Details body whose `type` is derived from `code`, so the two can never
 * disagree on the wire.
 *
 * `not_recognized` is the anti-enumeration error: it is built without the pending and
 * owner-action members even when the caller supplies them, because disclosing them would
 * reveal that the identity was recognized.
 */
export function createProblemDetails(input: CreateProblemDetailsInput): AepProblemDetails {
  if (!ERROR_CODE_PATTERN.test(input.code)) {
    throw new TypeError("AEP error codes use lowercase underscore-separated tokens.");
  }

  if (input.title.length === 0) {
    throw new TypeError("AEP Problem Details require a non-empty title.");
  }

  if (!Number.isInteger(input.status) || input.status < 100 || input.status > 599) {
    throw new TypeError("AEP Problem Details require an HTTP status code.");
  }

  const problem: AepProblemDetails = {
    type: `urn:aep:error:${input.code}`,
    title: input.title,
    status: input.status,
    code: input.code
  };

  if (input.detail !== undefined) {
    problem.detail = input.detail;
  }

  if (input.instance !== undefined) {
    problem.instance = input.instance;
  }

  if (input.code === "not_recognized") {
    return problem;
  }

  if (input.verification_pending !== undefined && input.verification_pending.length > 0) {
    problem.verification_pending = [...input.verification_pending];
  }

  if (input.requirements_pending !== undefined && input.requirements_pending.length > 0) {
    problem.requirements_pending = [...input.requirements_pending];
  }

  if (input.owner_action_required === true) {
    problem.owner_action_required = "true";
  }

  return problem;
}
