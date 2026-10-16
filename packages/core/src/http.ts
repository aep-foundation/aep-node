import {
  AEP_AUTHORIZATION_HEADER,
  AEP_IDEMPOTENCY_KEY_HEADER,
  DEFAULT_HTTP_ENDPOINT_BASE
} from "./constants.js";
import { AepAuthorizationCarrierError, AepIdempotencyError } from "./errors.js";
import type {
  AepCommand,
  AepProtectedResourceAuthorization,
  AepProtectedResourceAuthorizationCarrier,
  AepProtectedResourceAuthorizationScheme,
  InspectDocument
} from "./types.js";

export type AepHttpCommand = Exclude<AepCommand, "inspect">;

const COMMAND_PATHS: Record<AepHttpCommand, string> = {
  enroll: "enroll",
  grant: "grant",
  revoke: "revoke",
  status: "status"
};

const AUTHORIZATION_SCHEMES: Record<string, AepProtectedResourceAuthorizationScheme> = {
  aep: "AEP",
  basic: "Basic",
  bearer: "Bearer"
};

/**
 * Visible ASCII excluding space, per the `token68`-style credential syntaxes used by the
 * AEP, Bearer, and Basic presentations. Rejecting everything else keeps CR, LF, NUL, and
 * other control characters out of rendered field values.
 */
const CREDENTIALS_PATTERN = /^[\x21-\x7e]+$/;
const AUTHORIZATION_PATTERN = /^(AEP|Bearer|Basic)[ \t]+([\x21-\x7e]+)[ \t]*$/i;

export function normalizeEndpointBase(endpointBase = DEFAULT_HTTP_ENDPOINT_BASE): string {
  if (!endpointBase.startsWith("/")) {
    throw new TypeError("AEP endpoint_base must start with '/'.");
  }

  return endpointBase.endsWith("/") ? endpointBase : `${endpointBase}/`;
}

export function commandPath(
  command: AepHttpCommand,
  endpointBase = DEFAULT_HTTP_ENDPOINT_BASE
): string {
  return `${normalizeEndpointBase(endpointBase)}${COMMAND_PATHS[command]}`;
}

export function commandPathFromInspect(document: InspectDocument, command: AepHttpCommand): string {
  return commandPath(command, document.http.endpoint_base);
}

export function protectedResourceAuthorizationHeaderName(
  carrier: AepProtectedResourceAuthorizationCarrier = "standard"
): "Authorization" | typeof AEP_AUTHORIZATION_HEADER {
  return carrier === "dedicated" ? AEP_AUTHORIZATION_HEADER : "Authorization";
}

/**
 * Renders one AEP-recognized credential into its field value.
 *
 * Credentials are rejected unless every character is visible ASCII, so a caller cannot
 * smuggle a second field, a second credential, or a header terminator through a credential
 * value that originated off the wire.
 */
export function renderProtectedResourceAuthorization(
  authorization: Omit<AepProtectedResourceAuthorization, "carrier"> & {
    carrier?: AepProtectedResourceAuthorizationCarrier;
  }
): Record<string, string> {
  if (authorization.credentials.length === 0) {
    throw new AepAuthorizationCarrierError(
      "Authorization credentials must not be empty.",
      "invalid_request"
    );
  }

  if (!CREDENTIALS_PATTERN.test(authorization.credentials)) {
    throw new AepAuthorizationCarrierError(
      "Authorization credentials must not contain whitespace or control characters.",
      "invalid_request"
    );
  }

  if (AUTHORIZATION_SCHEMES[authorization.scheme.toLowerCase()] !== authorization.scheme) {
    throw new AepAuthorizationCarrierError(
      "Expected an AEP, Bearer, or Basic authentication scheme.",
      "invalid_request"
    );
  }

  return {
    [protectedResourceAuthorizationHeaderName(authorization.carrier)]:
      `${authorization.scheme} ${authorization.credentials}`
  };
}

/**
 * Parses one AEP-recognized credential presentation.
 *
 * A value carrying more than one credential fails closed rather than resolving to the first
 * match, so credential smuggling cannot select which credential the Service evaluates.
 */
export function parseProtectedResourceAuthorization(
  value: string,
  carrier: AepProtectedResourceAuthorizationCarrier = "standard"
): AepProtectedResourceAuthorization {
  if (carrier === "dedicated" && value.includes(",")) {
    throw new AepAuthorizationCarrierError(
      "The dedicated authorization field is ambiguous.",
      "not_recognized"
    );
  }

  const match = AUTHORIZATION_PATTERN.exec(value);
  const scheme = recognizedScheme(match);
  const credentials = match?.[2];

  if (scheme === undefined || credentials === undefined) {
    throw new AepAuthorizationCarrierError(
      "The authorization presentation was not recognized.",
      "not_recognized"
    );
  }

  return { carrier, credentials, scheme };
}

export interface SelectProtectedResourceAuthorizationInput {
  /** The value of the dedicated `AEP-Authorization` field, when the request carried one. */
  aepAuthorization?: string | string[] | undefined;
  /** The value of the standard `Authorization` field, when the request carried one. */
  authorization?: string | string[] | undefined;
}

/**
 * Chooses which field a protected resource evaluates.
 *
 * The dedicated field is inspected first and the standard field is consulted only when the
 * dedicated field is absent, so an invalid dedicated credential never falls back to a second
 * AEP credential. A request presenting an AEP-recognized credential in both fields, repeating
 * the dedicated field, or combining credentials in one dedicated value is treated as smuggling
 * and rejected without disclosing which credential was at fault.
 *
 * Returns `undefined` when neither field carries an AEP-recognized credential, which the caller
 * reports as `authentication_required` rather than as a recognition failure.
 */
export function selectProtectedResourceAuthorization(
  input: SelectProtectedResourceAuthorizationInput
): AepProtectedResourceAuthorization | undefined {
  const dedicated = singleFieldValue(input.aepAuthorization, AEP_AUTHORIZATION_HEADER);
  const standard = singleFieldValue(input.authorization, "Authorization");

  if (dedicated !== undefined) {
    const selected = parseProtectedResourceAuthorization(dedicated, "dedicated");

    if (standard !== undefined && isAepRecognized(standard)) {
      throw new AepAuthorizationCarrierError(
        "The request presented more than one AEP credential.",
        "not_recognized"
      );
    }

    return selected;
  }

  if (standard === undefined || !isAepRecognized(standard)) {
    return undefined;
  }

  return parseProtectedResourceAuthorization(standard, "standard");
}

function singleFieldValue(value: string | string[] | undefined, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    return value;
  }

  if (value.length === 0) {
    return undefined;
  }

  if (value.length > 1) {
    throw new AepAuthorizationCarrierError(`The ${field} field must not repeat.`, "not_recognized");
  }

  return value[0];
}

function recognizedScheme(
  match: RegExpExecArray | null
): AepProtectedResourceAuthorizationScheme | undefined {
  const scheme = match?.[1];
  return scheme === undefined ? undefined : AUTHORIZATION_SCHEMES[scheme.toLowerCase()];
}

function isAepRecognized(value: string): boolean {
  return recognizedScheme(AUTHORIZATION_PATTERN.exec(value)) !== undefined;
}

export interface ResolveIdempotencyKeyInput {
  /** The `Idempotency-Key` request field value. */
  header?: string | string[] | undefined;
  /** The Enroll request body's optional `idempotency_key` copy. */
  body?: string | undefined;
}

/**
 * Resolves the idempotency key for a state-mutating command.
 *
 * The header is required and the body copy is optional, but when both are present they must
 * carry the same value. Every rejection maps to `invalid_request`, which is the status a
 * Service returns for a missing, empty, repeated, or contradictory key.
 */
export function resolveIdempotencyKey(input: ResolveIdempotencyKeyInput): string {
  const header = Array.isArray(input.header) ? input.header : [input.header];

  if (header.length > 1) {
    throw new AepIdempotencyError(`The ${AEP_IDEMPOTENCY_KEY_HEADER} field must not repeat.`);
  }

  const key = header[0];

  if (key === undefined || key.length === 0) {
    throw new AepIdempotencyError(`Expected a non-empty ${AEP_IDEMPOTENCY_KEY_HEADER} field.`);
  }

  if (input.body !== undefined && input.body !== key) {
    throw new AepIdempotencyError(
      `Expected idempotency_key to match the ${AEP_IDEMPOTENCY_KEY_HEADER} field.`
    );
  }

  return key;
}
