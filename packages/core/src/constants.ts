export const AEP_VERSION = "1.0";

export const AEP_MEDIA_TYPE = "application/aep+json";
export const AEP_PROBLEM_MEDIA_TYPE = "application/problem+json";
export const AEP_AUTH_SCHEME = "AEP";
export const AEP_WELL_KNOWN_PATH = "/.well-known/aep";
export const DEFAULT_HTTP_ENDPOINT_BASE = "/aep/";

export const AEP_COMMANDS = ["inspect", "enroll", "grant", "revoke", "status"] as const;
export const AEP_AUTHENTICATED_COMMANDS = ["enroll", "grant", "revoke", "status"] as const;

export const AEP_BINDINGS = ["http"] as const;
export const AEP_SIGNING_ALGORITHMS = ["EdDSA", "ES256"] as const;

export const AEP_IDENTITY_METHOD_DID_WEB = "did:web";

export const AEP_GRANT_TYPE_OAUTH_BEARER = "oauth-bearer";
export const AEP_GRANT_TYPE_API_KEY = "api-key";
export const AEP_GRANT_TYPE_BASIC = "basic";

export const AEP_BUILT_IN_GRANT_TYPES = [
  AEP_GRANT_TYPE_OAUTH_BEARER,
  AEP_GRANT_TYPE_API_KEY,
  AEP_GRANT_TYPE_BASIC
] as const;
