import type {
  AEP_BINDINGS,
  AEP_BUILT_IN_GRANT_TYPES,
  AEP_ASSERTION_OPERATIONS,
  AEP_CLAIM_NAMES,
  AEP_COMMANDS,
  AEP_SIGNING_ALGORITHMS
} from "./constants.js";

export type AepCommand = (typeof AEP_COMMANDS)[number];
export type AepBinding = (typeof AEP_BINDINGS)[number];
export type AepExtensibleString<TValue extends string> = TValue | (string & Record<never, never>);
export type AepAdvertisedCommand = AepExtensibleString<AepCommand>;
export type AepAdvertisedBinding = AepExtensibleString<AepBinding>;
export type AepSigningAlgorithm = AepExtensibleString<(typeof AEP_SIGNING_ALGORITHMS)[number]>;
export type AepBuiltInGrantType = (typeof AEP_BUILT_IN_GRANT_TYPES)[number];
export type AepGrantType = AepExtensibleString<AepBuiltInGrantType>;
export type AepIdentityMethod = string;
export type AepAuthenticatedCommand = Exclude<AepCommand, "inspect">;
export type AepAssertionOperation = (typeof AEP_ASSERTION_OPERATIONS)[number];
export type AepAuthenticationMethod = AepExtensibleString<"aep-jwt" | AepBuiltInGrantType>;
export interface AepGrantTypeConfig {
  supports_per_credential_revoke?: "false" | "true";
  [key: string]: unknown;
}
export type AepOpenApiTrailingSlashMode = "strict" | "equivalent";
export type AepProtectedResourceAuthorizationCarrier = "standard" | "dedicated";
export type AepProtectedResourceAuthorizationScheme = "AEP" | "Bearer" | "Basic";
export type AepRegisteredClaimName = (typeof AEP_CLAIM_NAMES)[number];
export type AepClaimName = AepExtensibleString<AepRegisteredClaimName>;

export interface AepContactAddressPrimaryClaimValue {
  city?: string;
  country: string;
  first_name: string;
  last_name: string;
  line1: string;
  line2?: string;
  line3?: string;
  postcode?: string;
  region?: string;
  [key: string]: unknown;
}

export interface AepClaimValues {
  "contact.address.primary"?: AepContactAddressPrimaryClaimValue;
  "contact.email"?: string;
  "contact.mobile"?: string;
  "person.birthdate"?: string;
  "person.first_name"?: string;
  "person.last_name"?: string;
  "person.username"?: string;
  [key: string]: unknown;
}

export interface AepInspectClaims {
  required?: AepClaimName[];
  preferred?: AepClaimName[];
  optional?: AepClaimName[];
  [key: string]: unknown;
}

export interface AepProtectedResourceAuthorization {
  carrier: AepProtectedResourceAuthorizationCarrier;
  credentials: string;
  scheme: AepProtectedResourceAuthorizationScheme;
}

export type AepAgentStatus =
  "active" | "pending" | "rejected" | "suspended" | "terminated" | "unavailable";
export type AepEnrollmentDecisionStatus = Extract<
  AepAgentStatus,
  "active" | "pending" | "rejected"
>;
export type AepEnrollmentStatus = AepEnrollmentDecisionStatus;

export interface InspectDocument {
  aep_version: string;
  authentication?: { methods: AepAuthenticationMethod[] };
  bindings: {
    supported: AepAdvertisedBinding[];
    [key: string]: unknown;
  };
  claims?: AepInspectClaims;
  commands: {
    supported: AepAdvertisedCommand[];
    grant_types?: AepGrantType[];
    grant_types_config?: Record<string, AepGrantTypeConfig>;
    [key: string]: unknown;
  };
  core: {
    signing_algorithms: AepSigningAlgorithm[];
    [key: string]: unknown;
  };
  extensions?: {
    supported?: string[];
    [key: string]: unknown;
  };
  http: {
    endpoint_base?: string;
    openapi?: {
      url: string;
      path_matching: { trailing_slash: AepOpenApiTrailingSlashMode };
    };
    [key: string]: unknown;
  };
  identity: {
    methods: AepIdentityMethod[];
    [key: string]: unknown;
  };
  service: {
    did: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface AepProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  code: AepExtensibleString<AepErrorCode>;
  owner_action_required?: "true";
  requirements_pending?: string[];
  verification_pending?: string[];
  [key: string]: unknown;
}

export type AepErrorCode =
  | "enrollment_failed"
  | "invalid_request"
  | "not_recognized"
  | "identity_suspended"
  | "identity_terminated"
  | "identity_unavailable"
  | "verification_pending"
  | "verification_timeout"
  | "requirements_unmet"
  | "rate_limited"
  | "unsupported_grant_type"
  | "idempotency_conflict"
  | "authentication_required"
  | "unsupported_authentication_method"
  | "insufficient_scope";

export interface EnrollRequest {
  agent_did: string;
  claims?: AepClaimValues;
  idempotency_key?: string;
  [key: string]: unknown;
}

export interface EnrollResponse {
  status: AepAgentStatus;
  owner_action_required?: "true" | "false";
  verification_pending?: string[];
  requirements_pending?: string[];
  [key: string]: unknown;
}

export interface StatusResponse {
  status: AepAgentStatus;
  owner_action_required?: "true" | "false";
  verification_pending?: string[];
  requirements_pending?: string[];
  since?: string;
  [key: string]: unknown;
}

export interface GrantRequest {
  grant_type: AepGrantType;
  requested_scopes?: string[];
  [key: string]: unknown;
}

export type RevokeRequest =
  | {
      grant_type: AepGrantType;
      credential_id?: never;
      all_grant_types?: never;
      [key: string]: unknown;
    }
  | {
      credential_id: string;
      grant_type: AepGrantType;
      all_grant_types?: never;
      [key: string]: unknown;
    }
  | {
      all_grant_types: "true";
      credential_id?: never;
      grant_type?: never;
      [key: string]: unknown;
    };

export type RevokeResponse = Record<string, never>;

export interface AepClientAssertionClaims {
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  jti: string;
  op: AepAssertionOperation;
  resource?: string;
  sub: string;
  [key: string]: unknown;
}

export interface OAuthBearerGrantResponse {
  access_token: string;
  credential_id: string;
  expires_at: string;
  scopes: string[];
  token_type: "Bearer";
  [key: string]: unknown;
}

export interface ApiKeyGrantResponse {
  api_key: string;
  credential_id: string;
  expires_at: string;
  header: string;
  scopes: string[];
  [key: string]: unknown;
}

export interface BasicGrantResponse {
  credential_id: string;
  expires_at: string;
  password: string;
  realm?: string;
  scopes: string[];
  username: string;
  [key: string]: unknown;
}

export type AepBuiltInGrantResponse =
  OAuthBearerGrantResponse | ApiKeyGrantResponse | BasicGrantResponse;

export interface ValidationIssue {
  path: string;
  message: string;
}

export type ValidationResult<T> =
  | {
      ok: true;
      value: T;
      issues: [];
    }
  | {
      ok: false;
      issues: ValidationIssue[];
    };
