import { createHash } from "node:crypto";

import {
  AEP_AUTH_SCHEME,
  AEP_AUTHORIZATION_HEADER,
  AEP_BINDINGS,
  AEP_BUILT_IN_GRANT_TYPES,
  AEP_IDENTITY_METHOD_DID_WEB,
  AEP_MEDIA_TYPE,
  AEP_PROBLEM_MEDIA_TYPE,
  AEP_SIGNING_ALGORITHMS,
  AEP_VERSION,
  DEFAULT_HTTP_ENDPOINT_BASE,
  createProblemDetails,
  decodeJwtUnverified,
  missingAepRequiredClaimNames,
  parseBuiltInGrantResponse,
  parseClientAssertionClaims,
  parseEnrollRequest,
  parseGrantRequest,
  parseInspectDocument,
  parseProtectedResourceAuthorization,
  parseRevokeRequest,
  resolveDidWebPublicKey,
  verifyClientAssertionJwt
} from "@aep-foundation/core";
import type {
  AepCommand,
  AepAuthenticationMethod,
  AepAgentStatus,
  AepAssertionOperation,
  AepClaimName,
  AepClaimValues,
  AepClientAssertionClaims,
  AepEnrollmentDecisionStatus,
  AepBuiltInGrantResponse,
  AepBuiltInGrantType,
  AepGrantType,
  AepGrantTypeConfig,
  AepIdentityMethod,
  AepProblemDetails,
  AepSigningAlgorithm,
  AepImportableJoseKey,
  DidWebFetchLike,
  ApiKeyGrantResponse,
  BasicGrantResponse,
  EnrollRequest,
  EnrollResponse,
  GrantRequest,
  InspectDocument,
  OAuthBearerGrantResponse,
  RevokeRequest,
  RevokeResponse
} from "@aep-foundation/core";

export type Awaitable<T> = T | Promise<T>;

export interface AepIdentityMethodDefinition {
  method: AepIdentityMethod;
}

export interface AepGrantTypeDefinition {
  grantType: AepGrantType;
  config?: AepGrantTypeConfig;
  handler?: AepGrantTypeHandler;
}

export interface AepGrantContext {
  agentDid: string;
  enrollment: AepEnrollmentRecord;
  grantType: AepGrantType;
}

export interface AepRevokeContext {
  agentDid: string;
  enrollment: AepEnrollmentRecord;
  grantType: AepGrantType;
}

export interface AepGrantTypeHandler {
  grant(request: GrantRequest, context: AepGrantContext): Awaitable<Record<string, unknown>>;
  revoke(request: RevokeRequest, context: AepRevokeContext): Awaitable<void>;
  authenticate?(
    input: AepCredentialAuthenticationInput
  ): Awaitable<AepAuthenticatedPrincipal | undefined>;
  hasCredentialPresentation?(input: AepCredentialAuthenticationInput): Awaitable<boolean>;
}

export interface AepCredentialAuthenticationInput {
  headers: Readonly<Record<string, string>>;
  now: Date;
}

export interface AepAuthenticatedPrincipal {
  agentDid: string;
  authenticationKind: "aep-jwt" | "session-credential";
  authenticationMethod: AepAuthenticationMethod;
  credentialId?: string;
  grantType?: AepGrantType;
  scopes?: string[];
}

export interface AuthenticateProtectedResourceOptions {
  headers: Headers | Readonly<Record<string, string | string[] | undefined>>;
  method: string;
  url: string | URL;
}

export type AuthenticateProtectedResourceResult =
  | { authenticated: true; principal: AepAuthenticatedPrincipal }
  | { authenticated: false; response: AepServiceResponse<AepProblemDetails> };

export interface AepServiceCredentialRecord {
  agentDid: string;
  createdAt: string;
  credential: AepBuiltInGrantResponse;
  credentialId: string;
  expiresAt: string;
  grantType: AepBuiltInGrantType;
  revokedAt?: string;
}

export interface AepServiceCredentialStore {
  findCredential(
    agentDid: string,
    grantType: AepBuiltInGrantType,
    credentialId: string
  ): Awaitable<AepServiceCredentialRecord | undefined>;
  listCredentials(
    agentDid?: string,
    grantType?: AepBuiltInGrantType
  ): Awaitable<AepServiceCredentialRecord[]>;
  revokeCredential(
    agentDid: string,
    grantType: AepBuiltInGrantType,
    credentialId: string,
    revokedAt: string
  ): Awaitable<void>;
  revokeGrantType(
    agentDid: string,
    grantType: AepBuiltInGrantType,
    revokedAt: string
  ): Awaitable<void>;
  saveCredential(record: AepServiceCredentialRecord): Awaitable<AepServiceCredentialRecord>;
}

export type AepBuiltInCredentialIssuer<TCredential extends AepBuiltInGrantResponse> = (
  request: GrantRequest,
  context: AepGrantContext
) => Awaitable<TCredential>;

export interface AepStoredCredentialGrantTypeOptions<TCredential extends AepBuiltInGrantResponse> {
  clock?: () => Date;
  config?: AepGrantTypeConfig;
  issue: AepBuiltInCredentialIssuer<TCredential>;
  store: AepServiceCredentialStore;
}

export interface AepServiceClaimsConfig {
  required?: AepClaimName[];
  preferred?: AepClaimName[];
  optional?: AepClaimName[];
  limits?: Partial<AepServiceClaimValueLimits>;
}

export interface AepServiceClaimValueLimits {
  maxEncodedBytes: number;
  maxMemberCount: number;
  maxObjectDepth: number;
  maxStringLength: number;
}

export const DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS: Readonly<AepServiceClaimValueLimits> =
  Object.freeze({
    maxEncodedBytes: 65_536,
    maxMemberCount: 128,
    maxObjectDepth: 8,
    maxStringLength: 4_096
  });

export interface AepServiceOptions {
  clock?: () => Date;
  clientAssertion?: AepClientAssertionConfig;
  commandIdempotencyStore?: AepCommandIdempotencyStore;
  clientAssertionVerifier?: AepClientAssertionVerifier;
  serviceDid: string;
  endpointBase?: string;
  identityMethods: AepIdentityMethodDefinition[];
  grantTypes?: AepGrantTypeDefinition[];
  authenticationMethods?: AepAuthenticationMethod[];
  inspectUrl?: string | URL;
  claims?: AepServiceClaimsConfig;
  enrollmentPolicy?: AepEnrollmentPolicy;
  enrollmentStore?: AepEnrollmentStore;
  replayStore?: AepClientAssertionReplayStore;
  signingAlgorithms?: AepSigningAlgorithm[];
  extensions?: string[];
  openapi?: {
    url: string;
    pathMatching: { trailingSlash: "strict" | "equivalent" };
  };
}

export interface AepEnrollmentDecision {
  ownerActionRequired?: boolean;
  verificationPending?: string[];
  requirementsPending?: string[];
  status?: AepEnrollmentDecisionStatus;
}

export interface AepEnrollmentPolicyContext {
  now: Date;
}

export interface AepEnrollmentPolicy {
  decideEnrollment(
    request: EnrollRequest,
    context: AepEnrollmentPolicyContext
  ): Awaitable<AepEnrollmentDecision>;
}

export interface AepClientAssertionConfig {
  allowInsecureLoopback?: boolean;
  clock?: () => Date;
  clockSkewSeconds?: number;
  maxTtlSeconds?: number;
}

export interface AepClientAssertionVerificationContext {
  clientAssertion: string;
  command: AepAssertionOperation;
  idempotencyKey?: string;
  resource?: string;
  serviceDid: string;
  signingAlgorithms: AepSigningAlgorithm[];
}

export type AepClientAssertionVerifier = (
  clientAssertion: string,
  context: AepClientAssertionVerificationContext
) => Awaitable<AepClientAssertionClaims>;

export interface JwtClientAssertionVerifierOptions {
  algorithms?: AepSigningAlgorithm[];
  clockTolerance?: number | string;
  currentDate?: Date;
  key: AepImportableJoseKey;
}

export interface DidWebClientAssertionVerifierOptions {
  allowInsecureLoopback?: boolean;
  fetch?: DidWebFetchLike;
}

export type HostedPlatformVerificationFetchLike = (
  input: URL | string,
  init?: RequestInit
) => Promise<HostedPlatformVerificationResponseLike>;

export interface HostedPlatformVerificationResponseLike {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export interface HostedPlatformClientAssertionVerifierOptions {
  authorization?: string;
  endpoint: string | URL;
  fetch?: HostedPlatformVerificationFetchLike;
}

export interface HostedPlatformVerificationResponse {
  agent_did?: string;
  agent_identity_id?: string;
  op?: AuthenticatedServiceCommand;
  reason: string;
  service_did: string;
  status?: string;
  verified: boolean;
}

export interface AepClientAssertionReplayRecord {
  expiresAt: number;
  jti: string;
  sub: string;
}

export interface AepClientAssertionReplayStore {
  consumeReplay(record: AepClientAssertionReplayRecord, now: number): Awaitable<boolean>;
}

export interface AepEnrollmentRecord {
  agentDid: string;
  claims: AepClaimValues;
  createdAt: string;
  ownerActionRequired: boolean;
  requirementsPending: string[];
  verificationPending?: string[];
  since: string;
  status: AepAgentStatus;
  updatedAt: string;
}

export interface AepEnrollmentStore {
  findEnrollment(agentDid: string): Awaitable<AepEnrollmentRecord | undefined>;
  saveEnrollment(record: AepEnrollmentRecord): Awaitable<AepEnrollmentRecord>;
}

export interface AepCommandIdempotencyRecord<TBody = unknown> {
  agentDid: string;
  body: TBody;
  command: AepIdempotentServiceCommand;
  contentType: string;
  headers?: Record<string, string>;
  createdAt: string;
  idempotencyKey: string;
  requestHash: string;
  status: number;
}

export interface AepCommandIdempotencyInput {
  agentDid: string;
  command: AepIdempotentServiceCommand;
  idempotencyKey: string;
  requestHash: string;
}

export type AepCommandIdempotencyResult<TBody = unknown> =
  | {
      record: AepCommandIdempotencyRecord;
      state: "replayed";
    }
  | {
      response: AepServiceResponse<TBody>;
      state: "created";
    }
  | {
      state: "conflict";
    };

export interface AepCommandIdempotencyStore {
  executeIdempotentCommand<TBody>(
    input: AepCommandIdempotencyInput,
    execute: () => Awaitable<AepServiceResponse<TBody>>
  ): Awaitable<AepCommandIdempotencyResult<TBody>>;
}

export interface AepServiceResponse<TBody = unknown> {
  body: TBody;
  contentType: string;
  headers?: Record<string, string>;
  status: number;
}

export interface AepAuthenticatedServiceOptions {
  clientAssertion: string;
  idempotencyKey?: string;
}

export type AuthenticatedServiceCommand = Exclude<AepCommand, "inspect">;
export type AepIdempotentServiceCommand = Extract<AepCommand, "enroll" | "grant" | "revoke">;

export interface AepIdempotentServiceOptions extends AepAuthenticatedServiceOptions {
  idempotencyKey: string;
}

export interface AepService {
  authenticateProtectedResource(
    options: AuthenticateProtectedResourceOptions
  ): Promise<AuthenticateProtectedResourceResult>;
  enroll(
    request: unknown,
    options: AepIdempotentServiceOptions
  ): Promise<AepServiceResponse<EnrollResponse | AepProblemDetails>>;
  grant(
    request: unknown,
    options: AepIdempotentServiceOptions
  ): Promise<AepServiceResponse<Record<string, unknown> | AepProblemDetails>>;
  inspectDocument(): InspectDocument;
  revoke(
    request: unknown,
    options: AepIdempotentServiceOptions
  ): Promise<AepServiceResponse<RevokeResponse | AepProblemDetails>>;
  status(
    options: AepAuthenticatedServiceOptions
  ): Promise<AepServiceResponse<StatusResponseBody | AepProblemDetails>>;
}

export function createAepService(options: AepServiceOptions): AepService {
  const inspectDocument = buildInspectDocument(options);
  const claimValueLimits = resolveClaimValueLimits(options.claims?.limits);
  const commandIdempotencyStore =
    options.commandIdempotencyStore ?? createInMemoryCommandIdempotencyStore();
  const enrollmentPolicy = options.enrollmentPolicy ?? createStaticEnrollmentPolicy();
  const enrollmentStore = options.enrollmentStore ?? createInMemoryEnrollmentStore();
  const grantHandlers = createGrantHandlerMap(options.grantTypes ?? []);
  const replayStore = options.replayStore ?? createInMemoryClientAssertionReplayStore();
  const signingAlgorithms = [...(options.signingAlgorithms ?? AEP_SIGNING_ALGORITHMS)];
  const authenticationOptions = (): AuthenticateClientAssertionOptions => ({
    replayStore,
    serviceDid: options.serviceDid,
    signingAlgorithms,
    ...(options.clientAssertion === undefined ? {} : { config: options.clientAssertion }),
    ...(options.clientAssertionVerifier === undefined
      ? {}
      : { verifier: options.clientAssertionVerifier })
  });

  return {
    authenticateProtectedResource: (request) =>
      authenticateProtectedResourceRequest(request, {
        authenticationMethods: options.authenticationMethods ?? [],
        grantHandlers,
        ...(options.inspectUrl === undefined ? {} : { inspectUrl: options.inspectUrl }),
        ...authenticationOptions()
      }),
    enroll: async (request, commandOptions) => {
      const authentication = await authenticateClientAssertion(
        "enroll",
        commandOptions,
        authenticationOptions()
      );

      if (!authentication.ok) {
        return authentication.response;
      }

      try {
        if (parseEnrollRequest(request).agent_did !== authentication.agentDid) {
          return problem("not_recognized", "Not recognized", 401);
        }
      } catch {
        return problem("invalid_request", "Invalid request", 400);
      }

      return handleEnrollRequest(request, {
        claimValueLimits,
        commandIdempotencyStore,
        requiredClaims: inspectDocument.claims?.required ?? [],
        store: enrollmentStore,
        ...(options.clock === undefined ? {} : { clock: options.clock }),
        policy: enrollmentPolicy,
        idempotencyKey: commandOptions.idempotencyKey
      });
    },
    grant: async (request, commandOptions) => {
      const authentication = await authenticateClientAssertion(
        "grant",
        commandOptions,
        authenticationOptions()
      );

      if (!authentication.ok) {
        return authentication.response;
      }

      return handleGrantRequest(request, {
        agentDid: authentication.agentDid,
        commandIdempotencyStore,
        handlers: grantHandlers,
        idempotencyKey: commandOptions.idempotencyKey,
        store: enrollmentStore
      });
    },
    inspectDocument: () => structuredClone(inspectDocument),
    revoke: async (request, commandOptions) => {
      const authentication = await authenticateClientAssertion(
        "revoke",
        commandOptions,
        authenticationOptions()
      );

      if (!authentication.ok) {
        return authentication.response;
      }

      return handleRevokeRequest(request, {
        agentDid: authentication.agentDid,
        commandIdempotencyStore,
        handlers: grantHandlers,
        idempotencyKey: commandOptions.idempotencyKey,
        store: enrollmentStore
      });
    },
    status: async (commandOptions) => {
      const authentication = await authenticateClientAssertion(
        "status",
        commandOptions,
        authenticationOptions()
      );

      if (!authentication.ok) {
        return authentication.response;
      }

      return handleStatusRequest(authentication.agentDid, {
        store: enrollmentStore
      });
    }
  };
}

export function buildInspectDocument(options: AepServiceOptions): InspectDocument {
  const identityMethods = uniqueBy(options.identityMethods, "method", "identity method").map(
    (definition) => definition.method
  );
  const grantTypes = uniqueBy(options.grantTypes ?? [], "grantType", "grant type");
  const supportedCommands: AepCommand[] =
    grantTypes.length > 0
      ? ["enroll", "grant", "inspect", "revoke", "status"]
      : ["enroll", "inspect", "status"];

  if (identityMethods.length === 0) {
    throw new TypeError("AEP Services must enable at least one identity method.");
  }

  const grantTypeConfig: Record<string, AepGrantTypeConfig> = {};
  for (const definition of grantTypes) {
    if (definition.config !== undefined) {
      grantTypeConfig[definition.grantType] = definition.config;
    }
  }

  const document: InspectDocument = {
    aep_version: AEP_VERSION,
    ...((options.authenticationMethods?.length ?? 0) > 0
      ? { authentication: { methods: [...(options.authenticationMethods ?? [])] } }
      : {}),
    bindings: {
      supported: [...AEP_BINDINGS]
    },
    claims: {
      required: [...(options.claims?.required ?? [])],
      preferred: [...(options.claims?.preferred ?? [])],
      optional: [...(options.claims?.optional ?? [])]
    },
    commands: {
      supported: supportedCommands,
      ...(grantTypes.length > 0
        ? {
            grant_types: grantTypes.map((definition) => definition.grantType)
          }
        : {}),
      ...(Object.keys(grantTypeConfig).length > 0
        ? {
            grant_types_config: grantTypeConfig
          }
        : {})
    },
    core: {
      signing_algorithms: [...(options.signingAlgorithms ?? AEP_SIGNING_ALGORITHMS)]
    },
    extensions: {
      supported: [...(options.extensions ?? [])]
    },
    http: {
      endpoint_base: options.endpointBase ?? DEFAULT_HTTP_ENDPOINT_BASE,
      ...(options.openapi === undefined
        ? {}
        : {
            openapi: {
              url: options.openapi.url,
              path_matching: { trailing_slash: options.openapi.pathMatching.trailingSlash }
            }
          })
    },
    identity: {
      methods: identityMethods
    },
    service: {
      did: options.serviceDid
    }
  };

  return parseInspectDocument(document);
}

export function didWebIdentityMethod(): AepIdentityMethodDefinition {
  return {
    method: AEP_IDENTITY_METHOD_DID_WEB
  };
}

export function oauthBearerGrantType(config?: AepGrantTypeConfig): AepGrantTypeDefinition {
  return grantType(AEP_BUILT_IN_GRANT_TYPES[0], config);
}

export function apiKeyGrantType(config?: AepGrantTypeConfig): AepGrantTypeDefinition {
  return grantType(AEP_BUILT_IN_GRANT_TYPES[1], config);
}

export function basicGrantType(config?: AepGrantTypeConfig): AepGrantTypeDefinition {
  return grantType(AEP_BUILT_IN_GRANT_TYPES[2], config);
}

export function grantType(
  grantType: AepGrantType,
  config?: AepGrantTypeConfig,
  handler?: AepGrantTypeHandler
): AepGrantTypeDefinition {
  return {
    grantType,
    ...(config === undefined ? {} : { config }),
    ...(handler === undefined ? {} : { handler })
  };
}

export function storedOAuthBearerGrantType(
  options: AepStoredCredentialGrantTypeOptions<OAuthBearerGrantResponse>
): AepGrantTypeDefinition {
  return storedBuiltInGrantType(AEP_BUILT_IN_GRANT_TYPES[0], options);
}

export function storedApiKeyGrantType(
  options: AepStoredCredentialGrantTypeOptions<ApiKeyGrantResponse>
): AepGrantTypeDefinition {
  return storedBuiltInGrantType(AEP_BUILT_IN_GRANT_TYPES[1], options);
}

export function storedBasicGrantType(
  options: AepStoredCredentialGrantTypeOptions<BasicGrantResponse>
): AepGrantTypeDefinition {
  return storedBuiltInGrantType(AEP_BUILT_IN_GRANT_TYPES[2], options);
}

export function createInMemoryEnrollmentStore(
  records: AepEnrollmentRecord[] = []
): AepEnrollmentStore {
  const enrollments = new Map<string, AepEnrollmentRecord>();

  records.forEach((record) => enrollments.set(record.agentDid, cloneEnrollmentRecord(record)));

  return {
    findEnrollment(agentDid) {
      const record = enrollments.get(agentDid);
      return record === undefined ? undefined : cloneEnrollmentRecord(record);
    },
    saveEnrollment(record) {
      const cloned = cloneEnrollmentRecord(record);
      enrollments.set(cloned.agentDid, cloned);
      return cloneEnrollmentRecord(cloned);
    }
  };
}

export function createInMemoryClientAssertionReplayStore(): AepClientAssertionReplayStore {
  const records = new Map<string, AepClientAssertionReplayRecord>();

  return {
    consumeReplay(record, now) {
      for (const [key, existing] of records) {
        if (existing.expiresAt <= now) {
          records.delete(key);
        }
      }

      if (records.has(replayKey(record.sub, record.jti))) {
        return false;
      }

      records.set(replayKey(record.sub, record.jti), { ...record });
      return true;
    }
  };
}

export function createInMemoryCommandIdempotencyStore(
  records: AepCommandIdempotencyRecord[] = []
): AepCommandIdempotencyStore {
  const idempotency = new Map<string, AepCommandIdempotencyRecord>();
  const pending = new Map<string, Promise<void>>();

  records.forEach((record) =>
    idempotency.set(
      idempotencyLookupKey(record.agentDid, record.idempotencyKey),
      cloneIdempotencyResponseRecord(record)
    )
  );

  return {
    async executeIdempotentCommand(input, execute) {
      const key = idempotencyLookupKey(input.agentDid, input.idempotencyKey);

      for (;;) {
        const existing = idempotency.get(key);

        if (existing !== undefined) {
          if (existing.command !== input.command || existing.requestHash !== input.requestHash) {
            return {
              state: "conflict"
            };
          }

          return {
            record: cloneIdempotencyResponseRecord(existing),
            state: "replayed"
          };
        }

        const pendingCommand = pending.get(key);

        if (pendingCommand === undefined) {
          break;
        }

        await pendingCommand;
      }

      let releasePending: (() => void) | undefined;
      const pendingCommand = new Promise<void>((resolve) => {
        releasePending = resolve;
      });

      pending.set(key, pendingCommand);

      try {
        const response = await execute();
        const record: AepCommandIdempotencyRecord = {
          agentDid: input.agentDid,
          body: structuredClone(response.body),
          command: input.command,
          contentType: response.contentType,
          ...(response.headers === undefined ? {} : { headers: { ...response.headers } }),
          createdAt: new Date().toISOString(),
          idempotencyKey: input.idempotencyKey,
          requestHash: input.requestHash,
          status: response.status
        };

        idempotency.set(key, cloneIdempotencyResponseRecord(record));

        return {
          response,
          state: "created"
        };
      } finally {
        pending.delete(key);
        releasePending?.();
      }
    }
  };
}

export function createStaticEnrollmentPolicy(
  decision: AepEnrollmentDecision = {}
): AepEnrollmentPolicy {
  return {
    decideEnrollment: () => ({
      ownerActionRequired: decision.ownerActionRequired ?? false,
      requirementsPending: [...(decision.requirementsPending ?? [])],
      verificationPending: [...(decision.verificationPending ?? [])],
      status: decision.status ?? "active"
    })
  };
}

export function createJwtClientAssertionVerifier(
  options: JwtClientAssertionVerifierOptions
): AepClientAssertionVerifier {
  return (clientAssertion, context) =>
    verifyClientAssertionJwt(clientAssertion, {
      algorithms: options.algorithms ?? context.signingAlgorithms,
      audience: context.serviceDid,
      key: options.key,
      ...(options.clockTolerance === undefined ? {} : { clockTolerance: options.clockTolerance }),
      ...(options.currentDate === undefined ? {} : { currentDate: options.currentDate })
    });
}

export function createDidWebClientAssertionVerifier(
  options: DidWebClientAssertionVerifierOptions = {}
): AepClientAssertionVerifier {
  return async (clientAssertion, context) => {
    const untrusted = decodeJwtUnverified(clientAssertion);
    const issuer = stringField(untrusted.payload, "iss");
    const kid = stringField(untrusted.header, "kid");
    const key = await resolveDidWebPublicKey({
      ...(options.allowInsecureLoopback === undefined
        ? {}
        : { allowInsecureLoopback: options.allowInsecureLoopback }),
      did: issuer,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      kid
    });

    return verifyClientAssertionJwt(clientAssertion, {
      ...(options.allowInsecureLoopback === undefined
        ? {}
        : { allowInsecureLoopback: options.allowInsecureLoopback }),
      algorithms: context.signingAlgorithms,
      audience: context.serviceDid,
      key
    });
  };
}

export function createHostedPlatformClientAssertionVerifier(
  options: HostedPlatformClientAssertionVerifierOptions
): AepClientAssertionVerifier {
  const fetchImpl = platformVerificationFetch(options.fetch);

  return async (clientAssertion, context) => {
    const claims = parseClientAssertionClaims(decodeJwtUnverified(clientAssertion).payload);
    const response = await fetchImpl(options.endpoint, {
      body: JSON.stringify({
        client_assertion: clientAssertion,
        op: context.command,
        ...(context.resource === undefined ? {} : { resource: context.resource }),
        service_did: context.serviceDid
      }),
      headers: {
        Accept: AEP_MEDIA_TYPE,
        ...(options.authorization === undefined ? {} : { Authorization: options.authorization }),
        "Content-Type": AEP_MEDIA_TYPE,
        "Idempotency-Key": context.idempotencyKey ?? claims.jti
      },
      method: "POST"
    });

    if (!response.ok) {
      throw new Error(`AEP hosted verification failed with HTTP ${response.status}.`);
    }

    const verification = parseHostedPlatformVerificationResponse(await response.json());
    if (
      !verification.verified ||
      verification.agent_did !== claims.sub ||
      verification.op !== context.command ||
      verification.service_did !== context.serviceDid
    ) {
      throw new Error("AEP hosted verification did not recognize the client assertion.");
    }

    return claims;
  };
}

export function clientAssertionFromAepAuthorization(
  authorization: string | null | undefined
): string {
  const prefix = `${AEP_AUTH_SCHEME} `;

  if (authorization?.startsWith(prefix)) {
    return authorization.slice(prefix.length);
  }

  return "";
}

export async function authenticateProtectedResource(
  service: Pick<AepService, "authenticateProtectedResource">,
  options: AuthenticateProtectedResourceOptions
): Promise<AuthenticateProtectedResourceResult> {
  return service.authenticateProtectedResource(options);
}

export function isActiveProtectedResourceAuthentication(
  result: AuthenticateProtectedResourceResult
): result is Extract<AuthenticateProtectedResourceResult, { authenticated: true }> {
  return result.authenticated;
}

export function createInMemoryServiceCredentialStore(
  records: AepServiceCredentialRecord[] = []
): AepServiceCredentialStore {
  const credentials = new Map<string, AepServiceCredentialRecord>();

  records.forEach((record) =>
    saveServiceCredential(credentials, credentialRecordWithParsedCredential(record))
  );

  return {
    findCredential(agentDid, grantTypeName, credentialId) {
      const record = credentials.get(credentialId);

      return record === undefined ||
        record.agentDid !== agentDid ||
        record.grantType !== grantTypeName
        ? undefined
        : cloneCredential(record);
    },
    listCredentials(agentDid, grantTypeName) {
      return [...credentials.values()]
        .filter(
          (record) =>
            (agentDid === undefined || record.agentDid === agentDid) &&
            (grantTypeName === undefined || record.grantType === grantTypeName)
        )
        .map(cloneCredential);
    },
    revokeCredential(agentDid, grantTypeName, credentialId, revokedAt) {
      const record = credentials.get(credentialId);

      if (record?.agentDid === agentDid && record.grantType === grantTypeName) {
        credentials.set(credentialId, {
          ...record,
          revokedAt
        });
      }
    },
    revokeGrantType(agentDid, grantTypeName, revokedAt) {
      for (const [key, record] of credentials) {
        if (record.agentDid === agentDid && record.grantType === grantTypeName) {
          credentials.set(key, {
            ...record,
            revokedAt
          });
        }
      }
    },
    saveCredential(record) {
      const parsed = credentialRecordWithParsedCredential(record);
      saveServiceCredential(credentials, parsed);
      return cloneCredential(parsed);
    }
  };
}

export interface HandleEnrollRequestOptions {
  claimValueLimits?: Partial<AepServiceClaimValueLimits>;
  clock?: () => Date;
  commandIdempotencyStore?: AepCommandIdempotencyStore;
  idempotencyKey: string;
  policy: AepEnrollmentPolicy;
  requiredClaims?: readonly AepClaimName[];
  store: AepEnrollmentStore;
}

export async function handleEnrollRequest(
  request: unknown,
  options: HandleEnrollRequestOptions
): Promise<AepServiceResponse<EnrollResponse | AepProblemDetails>> {
  let parsed: EnrollRequest;

  try {
    parsed = parseEnrollRequest(request);
  } catch {
    return problem("invalid_request", "Invalid request", 400);
  }

  if (!isNonEmptyIdempotencyKey(options.idempotencyKey)) {
    return problem("invalid_request", "Invalid request", 400);
  }

  if (parsed.idempotency_key !== undefined && options.idempotencyKey !== parsed.idempotency_key) {
    return problem("invalid_request", "Invalid request", 400);
  }

  if (!claimValuesWithinLimits(parsed.claims, resolveClaimValueLimits(options.claimValueLimits))) {
    return problem("invalid_request", "Invalid request", 400);
  }

  return withIdempotency<EnrollResponse | AepProblemDetails>(
    "enroll",
    parsed.agent_did,
    options.idempotencyKey,
    parsed,
    options.commandIdempotencyStore,
    async () => {
      const existing = await options.store.findEnrollment(parsed.agent_did);
      if (existing !== undefined) {
        return aepResponse(200, enrollmentResponseFromRecord(existing));
      }

      const missingRequiredClaims = missingAepRequiredClaimNames(
        options.requiredClaims ?? [],
        parsed.claims
      );
      if (missingRequiredClaims.length > 0) {
        return requirementsUnmet(missingRequiredClaims);
      }

      const now = options.clock ?? (() => new Date());
      const nowDate = now();
      const nowIso = nowDate.toISOString();
      const decision = await options.policy.decideEnrollment(parsed, { now: nowDate });
      const record = await options.store.saveEnrollment({
        agentDid: parsed.agent_did,
        claims: structuredClone(parsed.claims ?? {}),
        createdAt: nowIso,
        ownerActionRequired: decision.ownerActionRequired ?? false,
        requirementsPending: [...(decision.requirementsPending ?? [])],
        verificationPending: [...(decision.verificationPending ?? [])],
        since: nowIso,
        status: decision.status ?? "active",
        updatedAt: nowIso
      });

      return aepResponse(200, enrollmentResponseFromRecord(record));
    }
  );
}

export interface HandleStatusRequestOptions {
  store: AepEnrollmentStore;
}

export type StatusResponseBody = {
  owner_action_required?: "true" | "false";
  requirements_pending?: string[];
  verification_pending?: string[];
  since: string;
  status: AepEnrollmentRecord["status"];
};

export async function handleStatusRequest(
  agentDid: string,
  options: HandleStatusRequestOptions
): Promise<AepServiceResponse<StatusResponseBody | AepProblemDetails>> {
  const record = await options.store.findEnrollment(agentDid);

  if (record === undefined) {
    return problem("not_recognized", "Not recognized", 401);
  }

  return aepResponse(200, statusResponseFromRecord(record));
}

export interface HandleGrantRequestOptions {
  agentDid: string;
  commandIdempotencyStore?: AepCommandIdempotencyStore;
  handlers: ReadonlyMap<AepGrantType, AepGrantTypeHandler>;
  idempotencyKey: string;
  store: AepEnrollmentStore;
}

export async function handleGrantRequest(
  request: unknown,
  options: HandleGrantRequestOptions
): Promise<AepServiceResponse<Record<string, unknown> | AepProblemDetails>> {
  let parsed: GrantRequest;

  try {
    parsed = parseGrantRequest(request);
  } catch {
    return problem("invalid_request", "Invalid request", 400);
  }

  if (!isNonEmptyIdempotencyKey(options.idempotencyKey)) {
    return problem("invalid_request", "Invalid request", 400);
  }

  const enrollment = await options.store.findEnrollment(options.agentDid);

  if (enrollment === undefined) {
    return problem("not_recognized", "Not recognized", 401);
  }

  if (enrollment.status !== "active") {
    return verificationPending(enrollment);
  }

  const handler = options.handlers.get(parsed.grant_type);

  if (handler === undefined) {
    return problem("unsupported_grant_type", "Unsupported grant type", 400);
  }

  return withIdempotency(
    "grant",
    options.agentDid,
    options.idempotencyKey,
    parsed,
    options.commandIdempotencyStore,
    async () =>
      aepResponse(
        200,
        await handler.grant(parsed, {
          agentDid: options.agentDid,
          enrollment,
          grantType: parsed.grant_type
        })
      )
  );
}

export interface HandleRevokeRequestOptions {
  agentDid: string;
  commandIdempotencyStore?: AepCommandIdempotencyStore;
  handlers: ReadonlyMap<AepGrantType, AepGrantTypeHandler>;
  idempotencyKey: string;
  store: AepEnrollmentStore;
}

export async function handleRevokeRequest(
  request: unknown,
  options: HandleRevokeRequestOptions
): Promise<AepServiceResponse<RevokeResponse | AepProblemDetails>> {
  let parsed: RevokeRequest;

  try {
    parsed = parseRevokeRequest(request);
  } catch {
    return problem("invalid_request", "Invalid request", 400);
  }

  if (!isNonEmptyIdempotencyKey(options.idempotencyKey)) {
    return problem("invalid_request", "Invalid request", 400);
  }

  const enrollment = await options.store.findEnrollment(options.agentDid);

  if (enrollment === undefined) {
    return problem("not_recognized", "Not recognized", 401);
  }

  if ("grant_type" in parsed) {
    const grantTypeName = parsed.grant_type;
    const handler = options.handlers.get(grantTypeName);

    if (handler === undefined) {
      return problem("unsupported_grant_type", "Unsupported grant type", 400);
    }

    return withIdempotency(
      "revoke",
      options.agentDid,
      options.idempotencyKey,
      parsed,
      options.commandIdempotencyStore,
      async () => {
        await handler.revoke(parsed, {
          agentDid: options.agentDid,
          enrollment,
          grantType: grantTypeName
        });
        return aepResponse(200, {});
      }
    );
  }

  return withIdempotency(
    "revoke",
    options.agentDid,
    options.idempotencyKey,
    parsed,
    options.commandIdempotencyStore,
    async () => {
      for (const [grantTypeName, handler] of options.handlers) {
        await handler.revoke(parsed, {
          agentDid: options.agentDid,
          enrollment,
          grantType: grantTypeName
        });
      }

      return aepResponse(200, {});
    }
  );
}

interface AuthenticateProtectedResourceRequestOptions extends AuthenticateClientAssertionOptions {
  authenticationMethods: AepAuthenticationMethod[];
  grantHandlers: ReadonlyMap<AepGrantType, AepGrantTypeHandler>;
  inspectUrl?: string | URL;
}

async function authenticateProtectedResourceRequest(
  request: AuthenticateProtectedResourceOptions,
  options: AuthenticateProtectedResourceRequestOptions
): Promise<AuthenticateProtectedResourceResult> {
  const normalized = normalizedHeaders(request.headers);
  const selected = selectProtectedResourceAuthorization(request.headers, normalized);
  if (!selected.ok) {
    return protectedResourceFailure("not_recognized", options, request.url);
  }
  const headers =
    selected.authorization === undefined
      ? normalized
      : { ...normalized, authorization: selected.authorization };
  const authorization = selected.authorization ?? normalized["authorization"];
  if (authorization?.toLowerCase().startsWith(`${AEP_AUTH_SCHEME.toLowerCase()} `)) {
    if (!options.authenticationMethods.includes("aep-jwt")) {
      return protectedResourceFailure("unsupported_authentication_method", options, request.url);
    }
    const authentication = await authenticateClientAssertion(
      "authenticate",
      { clientAssertion: authorization.slice(AEP_AUTH_SCHEME.length + 1) },
      options,
      new URL(request.url).toString()
    );
    return authentication.ok
      ? {
          authenticated: true,
          principal: {
            agentDid: authentication.agentDid,
            authenticationKind: "aep-jwt",
            authenticationMethod: "aep-jwt"
          }
        }
      : { authenticated: false, response: authentication.response };
  }

  const now = options.config?.clock?.() ?? new Date();
  let presented = authorization !== undefined;
  for (const method of options.authenticationMethods) {
    if (method === "aep-jwt") continue;
    const handler = options.grantHandlers.get(method);
    if (handler?.authenticate === undefined) continue;
    const input = { headers, now };
    presented ||= (await handler.hasCredentialPresentation?.(input)) ?? false;
    const principal = await handler.authenticate(input);
    if (principal !== undefined) return { authenticated: true, principal };
  }
  return protectedResourceFailure(
    presented ? "not_recognized" : "authentication_required",
    options,
    request.url
  );
}

function selectProtectedResourceAuthorization(
  source: AuthenticateProtectedResourceOptions["headers"],
  headers: Readonly<Record<string, string>>
): { ok: true; authorization?: string } | { ok: false } {
  const dedicated = headers[AEP_AUTHORIZATION_HEADER.toLowerCase()];
  if (dedicated === undefined) return { ok: true };
  if (hasDuplicateHeader(source, AEP_AUTHORIZATION_HEADER)) return { ok: false };
  try {
    parseProtectedResourceAuthorization(dedicated, "dedicated");
  } catch {
    return { ok: false };
  }
  const standard = headers["authorization"];
  if (standard !== undefined) {
    try {
      parseProtectedResourceAuthorization(standard, "standard");
      return { ok: false };
    } catch {
      // An unrelated Authorization scheme composes with the dedicated AEP field.
    }
  }
  return { ok: true, authorization: dedicated };
}

function hasDuplicateHeader(
  headers: AuthenticateProtectedResourceOptions["headers"],
  name: string
): boolean {
  if (isHeaders(headers)) return (headers.get(name) ?? "").includes(",");
  const values = Object.entries(headers).filter(
    ([candidate]) => candidate.toLowerCase() === name.toLowerCase()
  );
  return values.length !== 1 || Array.isArray(values[0]?.[1]);
}

function protectedResourceFailure(
  code: "authentication_required" | "not_recognized" | "unsupported_authentication_method",
  options: AuthenticateProtectedResourceRequestOptions,
  resource: string | URL
): AuthenticateProtectedResourceResult {
  const response = problem(code, code.replaceAll("_", " "), 401);
  const inspect = options.inspectUrl ?? new URL("/.well-known/aep", new URL(resource).origin);
  response.headers = {
    "WWW-Authenticate": `${AEP_AUTH_SCHEME} service_did="${options.serviceDid}", inspect="${String(inspect)}", reason="${code}"`
  };
  return { authenticated: false, response };
}

function normalizedHeaders(
  headers: AuthenticateProtectedResourceOptions["headers"]
): Record<string, string> {
  const result: Record<string, string> = {};
  if (isHeaders(headers)) {
    headers.forEach((value, name) => (result[name.toLowerCase()] = value));
    return result;
  }
  for (const [name, value] of Object.entries(headers)) {
    const selected = Array.isArray(value) ? value.join(", ") : value;
    if (selected !== undefined) result[name.toLowerCase()] = selected;
  }
  return result;
}

function isHeaders(value: AuthenticateProtectedResourceOptions["headers"]): value is Headers {
  return typeof Headers !== "undefined" && value instanceof Headers;
}

interface AuthenticateClientAssertionOptions {
  config?: AepClientAssertionConfig;
  replayStore: AepClientAssertionReplayStore;
  serviceDid: string;
  signingAlgorithms: AepSigningAlgorithm[];
  verifier?: AepClientAssertionVerifier;
}

type AuthenticateClientAssertionResult =
  | {
      agentDid: string;
      claims: AepClientAssertionClaims;
      ok: true;
    }
  | {
      ok: false;
      response: AepServiceResponse<AepProblemDetails>;
    };

async function authenticateClientAssertion(
  command: AepAssertionOperation,
  commandOptions: AepAuthenticatedServiceOptions,
  options: AuthenticateClientAssertionOptions,
  resource?: string
): Promise<AuthenticateClientAssertionResult> {
  if (options.verifier === undefined) {
    return notRecognized();
  }

  let claims: AepClientAssertionClaims;

  try {
    claims = parseClientAssertionClaims(
      await options.verifier(commandOptions.clientAssertion, {
        clientAssertion: commandOptions.clientAssertion,
        command,
        ...(commandOptions.idempotencyKey === undefined
          ? {}
          : { idempotencyKey: commandOptions.idempotencyKey }),
        ...(resource === undefined ? {} : { resource }),
        serviceDid: options.serviceDid,
        signingAlgorithms: options.signingAlgorithms
      }),
      {
        ...(options.config?.allowInsecureLoopback === undefined
          ? {}
          : { allowInsecureLoopback: options.config.allowInsecureLoopback })
      }
    );
  } catch {
    return notRecognized();
  }

  if (!validateClientAssertionClaimsForCommand(claims, command, options, resource)) {
    return notRecognized();
  }

  const clock = options.config?.clock ?? (() => new Date());
  const now = Math.floor(clock().getTime() / 1000);
  const consumed = await options.replayStore.consumeReplay(
    {
      expiresAt: claims.exp + (options.config?.clockSkewSeconds ?? 30),
      jti: claims.jti,
      sub: claims.sub
    },
    now
  );

  if (!consumed) {
    return notRecognized();
  }

  return {
    agentDid: claims.sub,
    claims,
    ok: true
  };
}

function validateClientAssertionClaimsForCommand(
  claims: AepClientAssertionClaims,
  command: AepAssertionOperation,
  options: AuthenticateClientAssertionOptions,
  resource?: string
): boolean {
  const clock = options.config?.clock ?? (() => new Date());
  const clockSkewSeconds = options.config?.clockSkewSeconds ?? 30;
  const maxTtlSeconds = options.config?.maxTtlSeconds ?? 300;
  const now = Math.floor(clock().getTime() / 1000);

  return (
    claims.iss === claims.sub &&
    claims.aud === options.serviceDid &&
    claims.op === command &&
    (command === "authenticate" ? claims.resource === resource : claims.resource === undefined) &&
    claims.exp > claims.iat &&
    claims.exp - claims.iat <= maxTtlSeconds &&
    claims.iat <= now + clockSkewSeconds &&
    claims.exp >= now - clockSkewSeconds
  );
}

function platformVerificationFetch(
  fetchImpl: HostedPlatformVerificationFetchLike | undefined
): HostedPlatformVerificationFetchLike {
  const resolved: unknown = fetchImpl ?? globalThis.fetch;

  if (typeof resolved !== "function") {
    throw new TypeError("AEP hosted Platform verification requires a fetch implementation.");
  }

  return resolved as HostedPlatformVerificationFetchLike;
}

function parseHostedPlatformVerificationResponse(
  value: unknown
): HostedPlatformVerificationResponse {
  if (!isRecord(value)) {
    throw new TypeError("AEP hosted verification response must be an object.");
  }

  return {
    ...(typeof value["agent_did"] === "string" ? { agent_did: value["agent_did"] } : {}),
    ...(typeof value["agent_identity_id"] === "string"
      ? { agent_identity_id: value["agent_identity_id"] }
      : {}),
    ...(isAuthenticatedServiceCommand(value["op"]) ? { op: value["op"] } : {}),
    reason: stringField(value, "reason"),
    service_did: stringField(value, "service_did"),
    ...(typeof value["status"] === "string" ? { status: value["status"] } : {}),
    verified: booleanField(value, "verified")
  };
}

function uniqueBy<T extends Record<K, string>, K extends keyof T>(
  items: T[],
  key: K,
  label: string
): T[] {
  const seen = new Set<string>();

  return items.map((item) => {
    const value = item[key];

    if (seen.has(value)) {
      throw new TypeError(`Duplicate AEP ${label}: ${value}.`);
    }

    seen.add(value);
    return item;
  });
}

function createGrantHandlerMap(
  grantTypes: AepGrantTypeDefinition[]
): ReadonlyMap<AepGrantType, AepGrantTypeHandler> {
  const handlers = new Map<AepGrantType, AepGrantTypeHandler>();

  for (const definition of grantTypes) {
    if (definition.handler !== undefined) {
      handlers.set(definition.grantType, definition.handler);
    }
  }

  return handlers;
}

function storedBuiltInGrantType<TCredential extends AepBuiltInGrantResponse>(
  grantTypeName: AepBuiltInGrantType,
  options: AepStoredCredentialGrantTypeOptions<TCredential>
): AepGrantTypeDefinition {
  const config = { ...options.config, supports_per_credential_revoke: "true" } as const;
  return grantType(grantTypeName, config, {
    async grant(request, context) {
      const credential = parseBuiltInGrantResponse(
        grantTypeName,
        await options.issue(request, context)
      );
      const record = await options.store.saveCredential({
        agentDid: context.agentDid,
        createdAt: (options.clock ?? (() => new Date()))().toISOString(),
        credential,
        credentialId: credential.credential_id,
        expiresAt: credential.expires_at,
        grantType: grantTypeName
      });

      return structuredClone(record.credential);
    },
    async revoke(request, context) {
      const revokedAt = (options.clock ?? (() => new Date()))().toISOString();

      if ("credential_id" in request) {
        await options.store.revokeCredential(
          context.agentDid,
          grantTypeName,
          request.credential_id,
          revokedAt
        );
        return;
      }

      await options.store.revokeGrantType(context.agentDid, grantTypeName, revokedAt);
    },
    async authenticate(input) {
      const records = await options.store.listCredentials(undefined, grantTypeName);
      for (const record of records) {
        if (record.revokedAt !== undefined || Date.parse(record.expiresAt) <= input.now.getTime()) {
          continue;
        }
        if (!credentialMatchesHeaders(record.credential, input.headers)) continue;
        return {
          agentDid: record.agentDid,
          authenticationKind: "session-credential",
          authenticationMethod: grantTypeName,
          credentialId: record.credentialId,
          grantType: grantTypeName,
          scopes: [...record.credential.scopes]
        };
      }
      return undefined;
    },
    async hasCredentialPresentation(input) {
      if (grantTypeName !== AEP_BUILT_IN_GRANT_TYPES[1]) {
        return input.headers["authorization"] !== undefined;
      }
      const records = await options.store.listCredentials(undefined, grantTypeName);
      return records.some(
        (record) =>
          "header" in record.credential &&
          typeof record.credential.header === "string" &&
          input.headers[record.credential.header.toLowerCase()] !== undefined
      );
    }
  });
}

function credentialMatchesHeaders(
  credential: AepBuiltInGrantResponse,
  headers: Readonly<Record<string, string>>
): boolean {
  if (typeof credential.access_token === "string") {
    return matchesAuthorizationCredential(
      headers["authorization"],
      "Bearer",
      credential.access_token
    );
  }
  if (typeof credential.api_key === "string" && typeof credential.header === "string") {
    return headers[credential.header.toLowerCase()] === credential.api_key;
  }
  const username = credential.username;
  const password = credential.password;
  if (typeof username !== "string" || typeof password !== "string") return false;
  return matchesAuthorizationCredential(
    headers["authorization"],
    "Basic",
    Buffer.from(`${username}:${password}`).toString("base64")
  );
}

function matchesAuthorizationCredential(
  value: string | undefined,
  scheme: "Bearer" | "Basic",
  credentials: string
): boolean {
  if (value === undefined) return false;
  try {
    const parsed = parseProtectedResourceAuthorization(value);
    return parsed.scheme === scheme && parsed.credentials === credentials;
  } catch {
    return false;
  }
}

function enrollmentResponseFromRecord(record: AepEnrollmentRecord): EnrollResponse {
  return {
    status: record.status,
    ...(record.ownerActionRequired
      ? {
          owner_action_required: "true" as const
        }
      : {}),
    ...(record.requirementsPending.length > 0
      ? {
          requirements_pending: [...record.requirementsPending]
        }
      : {}),
    ...((record.verificationPending?.length ?? 0) > 0
      ? { verification_pending: [...(record.verificationPending ?? [])] }
      : {})
  };
}

function statusResponseFromRecord(record: AepEnrollmentRecord): StatusResponseBody {
  return {
    ...(record.ownerActionRequired ? { owner_action_required: "true" as const } : {}),
    ...(record.requirementsPending.length > 0
      ? { requirements_pending: [...record.requirementsPending] }
      : {}),
    ...((record.verificationPending?.length ?? 0) > 0
      ? { verification_pending: [...(record.verificationPending ?? [])] }
      : {}),
    since: record.since,
    status: record.status
  };
}

function aepResponse<TBody>(status: number, body: TBody): AepServiceResponse<TBody> {
  return {
    body,
    contentType: AEP_MEDIA_TYPE,
    status
  };
}

function problem(
  code: string,
  title: string,
  status: number
): AepServiceResponse<AepProblemDetails> {
  return {
    body: createProblemDetails({
      code,
      status,
      title
    }),
    contentType: AEP_PROBLEM_MEDIA_TYPE,
    ...(status === 401 ? { headers: { "WWW-Authenticate": `AEP reason="${code}"` } } : {}),
    status
  };
}

function requirementsUnmet(
  requirementsPending: readonly AepClaimName[]
): AepServiceResponse<AepProblemDetails> {
  const response = problem("requirements_unmet", "Requirements unmet", 422);
  response.body.requirements_pending = [...requirementsPending];
  return response;
}

function verificationPending(
  enrollment: AepEnrollmentRecord
): AepServiceResponse<AepProblemDetails> {
  const response = problem("verification_pending", "Verification pending", 403);
  if (enrollment.ownerActionRequired) {
    response.body.owner_action_required = "true";
  }
  if (enrollment.requirementsPending.length > 0) {
    response.body.requirements_pending = [...enrollment.requirementsPending];
  }
  if ((enrollment.verificationPending?.length ?? 0) > 0) {
    response.body.verification_pending = [...(enrollment.verificationPending ?? [])];
  }
  return response;
}

function resolveClaimValueLimits(
  configured: Partial<AepServiceClaimValueLimits> | undefined
): AepServiceClaimValueLimits {
  const limits = {
    ...DEFAULT_AEP_SERVICE_CLAIM_VALUE_LIMITS,
    ...configured
  };

  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`${name} must be a positive safe integer.`);
    }
  }

  return limits;
}

function claimValuesWithinLimits(
  claims: AepClaimValues | undefined,
  limits: AepServiceClaimValueLimits
): boolean {
  if (claims === undefined) return true;

  const state = {
    memberCount: 0,
    visiting: new Set<object>()
  };
  if (!claimValueWithinLimits(claims, 1, limits, state)) return false;

  try {
    const encoded = JSON.stringify(claims);
    return new TextEncoder().encode(encoded).byteLength <= limits.maxEncodedBytes;
  } catch {
    return false;
  }
}

function claimValueWithinLimits(
  value: unknown,
  depth: number,
  limits: AepServiceClaimValueLimits,
  state: { memberCount: number; visiting: Set<object> }
): boolean {
  if (typeof value === "string") {
    return [...value].length <= limits.maxStringLength;
  }
  if (
    value === null ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return true;
  }
  if (typeof value !== "object" || depth > limits.maxObjectDepth) return false;
  if (state.visiting.has(value)) return false;

  if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype) return false;

  state.visiting.add(value);
  const entries = Array.isArray(value) ? value.entries() : Object.entries(value);

  for (const [key, memberValue] of entries) {
    if (typeof key === "string") {
      state.memberCount += 1;
      if (state.memberCount > limits.maxMemberCount || [...key].length > limits.maxStringLength) {
        state.visiting.delete(value);
        return false;
      }
    }
    if (!claimValueWithinLimits(memberValue, depth + 1, limits, state)) {
      state.visiting.delete(value);
      return false;
    }
  }

  state.visiting.delete(value);
  return true;
}

function notRecognized(): AuthenticateClientAssertionResult {
  return {
    ok: false,
    response: problem("not_recognized", "Not recognized", 401)
  };
}

async function withIdempotency<TBody>(
  command: AepIdempotentServiceCommand,
  agentDid: string,
  idempotencyKey: string,
  request: unknown,
  store: AepCommandIdempotencyStore | undefined,
  execute: () => Promise<AepServiceResponse<TBody>>
): Promise<AepServiceResponse<TBody | AepProblemDetails>> {
  if (store === undefined) {
    return execute();
  }

  const requestHash = hashRequest(request);
  const result = await store.executeIdempotentCommand(
    {
      agentDid,
      command,
      idempotencyKey,
      requestHash
    },
    execute
  );

  if (result.state === "replayed") {
    return {
      body: structuredClone(result.record.body) as TBody,
      contentType: result.record.contentType,
      ...(result.record.headers === undefined ? {} : { headers: { ...result.record.headers } }),
      status: result.record.status
    };
  }

  if (result.state === "conflict") {
    return problem("idempotency_conflict", "Idempotency conflict", 409);
  }

  return result.response;
}

function replayKey(sub: string, jti: string): string {
  return `${sub}\u0000${jti}`;
}

function idempotencyLookupKey(agentDid: string, idempotencyKey: string): string {
  return `${agentDid}\u0000${idempotencyKey}`;
}

function cloneEnrollmentRecord(record: AepEnrollmentRecord): AepEnrollmentRecord {
  return {
    ...record,
    claims: structuredClone(record.claims),
    requirementsPending: [...record.requirementsPending],
    verificationPending: [...(record.verificationPending ?? [])]
  };
}

function cloneIdempotencyResponseRecord(
  record: AepCommandIdempotencyRecord
): AepCommandIdempotencyRecord {
  return {
    ...record,
    body: structuredClone(record.body),
    ...(record.headers === undefined ? {} : { headers: { ...record.headers } })
  };
}

function saveServiceCredential(
  credentials: Map<string, AepServiceCredentialRecord>,
  record: AepServiceCredentialRecord
): void {
  if (credentials.has(record.credentialId)) {
    throw new TypeError(`AEP credential identifier is already issued: ${record.credentialId}.`);
  }
  credentials.set(record.credentialId, cloneCredential(record));
}

function cloneCredential(record: AepServiceCredentialRecord): AepServiceCredentialRecord {
  return {
    ...record,
    credential: structuredClone(record.credential)
  };
}

function credentialRecordWithParsedCredential(
  record: AepServiceCredentialRecord
): AepServiceCredentialRecord {
  const credential = parseBuiltInGrantResponse(record.grantType, record.credential);

  if (credential.credential_id !== record.credentialId) {
    throw new TypeError("AEP credential record credentialId does not match credential body.");
  }

  if (credential.expires_at !== record.expiresAt) {
    throw new TypeError("AEP credential record expiresAt does not match credential body.");
  }

  return {
    ...record,
    credential
  };
}

function hashRequest(request: unknown): string {
  return `sha256:${createHash("sha256").update(stableStringify(request)).digest("hex")}`;
}

function isNonEmptyIdempotencyKey(value: string): boolean {
  return value.trim().length > 0;
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

function stringField(value: unknown, field: string): string {
  if (!isRecord(value) || typeof value[field] !== "string") {
    throw new Error(`Expected string field: ${field}`);
  }

  return value[field];
}

function booleanField(value: unknown, field: string): boolean {
  if (!isRecord(value) || typeof value[field] !== "boolean") {
    throw new Error(`Expected boolean field: ${field}`);
  }

  return value[field];
}

function isAuthenticatedServiceCommand(value: unknown): value is AuthenticatedServiceCommand {
  return value === "enroll" || value === "grant" || value === "revoke" || value === "status";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
