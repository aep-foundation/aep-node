import type {
  AepErrorCode,
  AepExtensibleString,
  AepProblemDetails,
  ValidationIssue
} from "./types.js";

export class AepValidationError extends Error {
  readonly issues: ValidationIssue[];

  constructor(message: string, issues: ValidationIssue[]) {
    super(message);
    this.name = "AepValidationError";
    this.issues = issues;
  }
}

export function createProblemDetails(input: {
  code: AepExtensibleString<AepErrorCode>;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  type?: string;
}): AepProblemDetails {
  const problem: AepProblemDetails = {
    type: input.type ?? `urn:aep:error:${input.code}`,
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

  return problem;
}
