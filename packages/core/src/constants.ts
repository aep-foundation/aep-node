export const AEP_VERSION = "1.0";

export const AEP_MEDIA_TYPE = "application/aep+json";
export const AEP_PROBLEM_MEDIA_TYPE = "application/problem+json";
export const AEP_AUTH_SCHEME = "AEP";
export const AEP_AUTHORIZATION_HEADER = "AEP-Authorization";
export const AEP_WELL_KNOWN_PATH = "/.well-known/aep";
export const DEFAULT_HTTP_ENDPOINT_BASE = "/aep/";

export const AEP_COMMANDS = ["inspect", "enroll", "grant", "revoke", "status"] as const;
export const AEP_AUTHENTICATED_COMMANDS = ["enroll", "grant", "revoke", "status"] as const;
export const AEP_ASSERTION_OPERATIONS = [...AEP_AUTHENTICATED_COMMANDS, "authenticate"] as const;
export const AEP_AUTHENTICATION_METHOD_JWT = "aep-jwt";

export const AEP_BINDINGS = ["http"] as const;
export const AEP_SIGNING_ALGORITHMS = ["EdDSA", "ES256"] as const;

export const AEP_IDENTITY_METHOD_DID_WEB = "did:web";

export const AEP_CLAIM_NAME_CONTACT_ADDRESS_PRIMARY = "contact.address.primary";
export const AEP_CLAIM_NAME_CONTACT_EMAIL = "contact.email";
export const AEP_CLAIM_NAME_CONTACT_MOBILE = "contact.mobile";
export const AEP_CLAIM_NAME_PERSON_BIRTHDATE = "person.birthdate";
export const AEP_CLAIM_NAME_PERSON_FIRST_NAME = "person.first_name";
export const AEP_CLAIM_NAME_PERSON_LAST_NAME = "person.last_name";
export const AEP_CLAIM_NAME_PERSON_USERNAME = "person.username";

export const AEP_CLAIM_NAMES = [
  AEP_CLAIM_NAME_CONTACT_ADDRESS_PRIMARY,
  AEP_CLAIM_NAME_CONTACT_EMAIL,
  AEP_CLAIM_NAME_CONTACT_MOBILE,
  AEP_CLAIM_NAME_PERSON_BIRTHDATE,
  AEP_CLAIM_NAME_PERSON_FIRST_NAME,
  AEP_CLAIM_NAME_PERSON_LAST_NAME,
  AEP_CLAIM_NAME_PERSON_USERNAME
] as const;

export const AEP_GRANT_TYPE_OAUTH_BEARER = "oauth-bearer";
export const AEP_GRANT_TYPE_API_KEY = "api-key";
export const AEP_GRANT_TYPE_BASIC = "basic";

export const AEP_BUILT_IN_GRANT_TYPES = [
  AEP_GRANT_TYPE_OAUTH_BEARER,
  AEP_GRANT_TYPE_API_KEY,
  AEP_GRANT_TYPE_BASIC
] as const;
