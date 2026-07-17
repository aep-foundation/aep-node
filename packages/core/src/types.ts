import type {
  AEP_BINDINGS,
  AEP_BUILT_IN_GRANT_TYPES,
  AEP_ASSERTION_OPERATIONS,
  AEP_COMMANDS,
  AEP_SIGNING_ALGORITHMS
} from "./constants.js";

export type AepCommand = (typeof AEP_COMMANDS)[number];
export type AepBinding = (typeof AEP_BINDINGS)[number];
export type AepExtensibleString<TValue extends string> = TValue | (string & Record<never, never>);
export type AepSigningAlgorithm = AepExtensibleString<(typeof AEP_SIGNING_ALGORITHMS)[number]>;
export type AepBuiltInGrantType = (typeof AEP_BUILT_IN_GRANT_TYPES)[number];
export type AepGrantType = AepExtensibleString<AepBuiltInGrantType>;
export type AepIdentityMethod = string;
export type AepAuthenticatedCommand = Exclude<AepCommand, "inspect">;
export type AepAssertionOperation = (typeof AEP_ASSERTION_OPERATIONS)[number];
export type AepAuthenticationMethod = AepExtensibleString<"aep-jwt" | AepBuiltInGrantType>;
export type AepOpenApiTrailingSlashMode = "strict" | "equivalent";
export type AepProtectedResourceAuthorizationCarrier = "standard" | "dedicated";
export type AepProtectedResourceAuthorizationScheme = "AEP" | "Bearer" | "Basic";

export interface AepProtectedResourceAuthorization {
  carrier: AepProtectedResourceAuthorizationCarrier;
  credentials: string;
  scheme: AepProtectedResourceAuthorizationScheme;
}

export type AepEnrollmentStatus = "active" | "pending" | "rejected";
export type AepAgentStatus = AepEnrollmentStatus | "suspended" | "terminated" | "unavailable";

export interface InspectDocument {
  aep_version: string;
  authentication?: { methods: AepAuthenticationMethod[] };
  bindings: {
    supported: AepBinding[];
    [key: string]: unknown;
  };
  claims?: {
    required?: string[];
    preferred?: string[];
    optional?: string[];
    [key: string]: unknown;
  };
  commands: {
    supported: AepCommand[];
    grant_types?: AepGrantType[];
    grant_types_config?: Record<string, unknown>;
    [key: string]: unknown;
  };
  core: {
    signing_algorithms?: AepSigningAlgorithm[];
    [key: string]: unknown;
  };
  extensions?: {
    supported?: string[];
    [key: string]: unknown;
  };
  http: {
    endpoint_base: string;
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
  [key: string]: unknown;
}

export type AepErrorCode =
  | "invalid_request"
  | "not_recognized"
  | "identity_suspended"
  | "identity_terminated"
  | "identity_unavailable"
  | "verification_pending"
  | "requirements_unmet"
  | "unsupported_grant_type"
  | "idempotency_conflict"
  | "authentication_required"
  | "unsupported_authentication_method"
  | "insufficient_scope";

export interface EnrollRequest {
  agent_did: string;
  claims?: Record<string, unknown>;
  idempotency_key: string;
  [key: string]: unknown;
}

export interface EnrollResponse {
  status: AepEnrollmentStatus;
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
      grant_type?: never;
      all_grant_types?: never;
      [key: string]: unknown;
    }
  | {
      all_grant_types: "true";
      credential_id?: string;
      grant_type?: AepGrantType;
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
