import { AEP_AUTHORIZATION_HEADER, DEFAULT_HTTP_ENDPOINT_BASE } from "./constants.js";
import { AepAuthorizationCarrierError } from "./errors.js";
import type {
  AepCommand,
  AepProtectedResourceAuthorization,
  AepProtectedResourceAuthorizationCarrier,
  InspectDocument
} from "./types.js";

export type AepHttpCommand = Exclude<AepCommand, "inspect">;

const COMMAND_PATHS: Record<AepHttpCommand, string> = {
  enroll: "enroll",
  grant: "grant",
  revoke: "revoke",
  status: "status"
};

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
  return {
    [protectedResourceAuthorizationHeaderName(authorization.carrier)]:
      `${authorization.scheme} ${authorization.credentials}`
  };
}

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
  const match = /^(AEP|Bearer|Basic) ([^\s].*)$/i.exec(value);
  if (match === null) {
    throw new AepAuthorizationCarrierError(
      "The authorization presentation was not recognized.",
      "not_recognized"
    );
  }
  const scheme = match[1]?.toLowerCase();
  return {
    carrier,
    credentials: match[2] ?? "",
    scheme: scheme === "aep" ? "AEP" : scheme === "bearer" ? "Bearer" : "Basic"
  };
}
