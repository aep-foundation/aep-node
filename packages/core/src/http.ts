import { DEFAULT_HTTP_ENDPOINT_BASE } from "./constants.js";
import type { AepCommand, InspectDocument } from "./types.js";

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
