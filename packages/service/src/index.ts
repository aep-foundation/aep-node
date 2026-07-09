import {
  AEP_AUTH_SCHEME,
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
  parseBuiltInGrantResponse,
  parseClientAssertionClaims,
  parseEnrollRequest,
  parseGrantRequest,
  parseInspectDocument,
  parseRevokeRequest,
  resolveDidWebPublicKey,
  verifyClientAssertionJwt
} from "@aep-foundation/core";
import type {
  AepCommand,
  AepClientAssertionClaims,
  AepEnrollmentStatus,
  AepBuiltInGrantResponse,
  AepBuiltInGrantType,
  AepGrantType,
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
  config?: Record<string, unknown>;
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
}

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
    agentDid: string,
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
  config?: Record<string, unknown>;
  issue: AepBuiltInCredentialIssuer<TCredential>;
  store: AepServiceCredentialStore;
}

export interface AepServiceClaimsConfig {
  required?: string[];
  preferred?: string[];
  optional?: string[];
}

export interface AepServiceOptions {
  clock?: () => Date;
  clientAssertion?: AepClientAssertionConfig;
  commandIdempotencyStore?: AepCommandIdempotencyStore;
  clientAssertionVerifier?: AepClientAssertionVerifier;
  serviceDid: string;
  endpointBase?: string;
  identityMethods: AepIdentityMethodDefinition[];
  grantTypes?: AepGrantTypeDefinition[];
  claims?: AepServiceClaimsConfig;
  enrollmentPolicy?: AepEnrollmentPolicy;
  enrollmentStore?: AepEnrollmentStore;
  replayStore?: AepClientAssertionReplayStore;
  signingAlgorithms?: AepSigningAlgorithm[];
  extensions?: string[];
}

export interface AepEnrollmentDecision {
  ownerActionRequired?: boolean;
  requirementsPending?: string[];
  status?: AepEnrollmentStatus;
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
  clock?: () => Date;
  clockSkewSeconds?: number;
  maxTtlSeconds?: number;
}

export interface AepClientAssertionVerificationContext {
  clientAssertion: string;
  command: AuthenticatedServiceCommand;
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
  claims: Record<string, unknown>;
  createdAt: string;
  ownerActionRequired: boolean;
  requirementsPending: string[];
  since: string;
  status: AepEnrollmentStatus;
  updatedAt: string;
}

export interface AepEnrollmentStore {
  findEnrollment(agentDid: string): Awaitable<AepEnrollmentRecord | undefined>;
  saveEnrollment(record: AepEnrollmentRecord): Awaitable<AepEnrollmentRecord>;
}

export interface AepCommandIdempotencyRecord<TBody = unknown> {
  agentDid: string;
  body: TBody;
  command: AuthenticatedServiceCommand;
  contentType: string;
  createdAt: string;
  idempotencyKey: string;
  requestHash: string;
  status: number;
}

export interface AepCommandIdempotencyInput {
  agentDid: string;
  command: AuthenticatedServiceCommand;
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
  status: number;
}

export interface AepAuthenticatedServiceOptions {
  clientAssertion: string;
  idempotencyKey?: string;
}

export type AuthenticatedServiceCommand = Exclude<AepCommand, "inspect">;

export interface AepService {
  enroll(
    request: unknown,
    options: AepAuthenticatedServiceOptions
  ): Promise<AepServiceResponse<EnrollResponse | AepProblemDetails>>;
  grant(
    request: unknown,
    options: AepAuthenticatedServiceOptions
  ): Promise<AepServiceResponse<Record<string, unknown> | AepProblemDetails>>;
  inspectDocument(): InspectDocument;
  revoke(
    request: unknown,
    options: AepAuthenticatedServiceOptions
  ): Promise<AepServiceResponse<RevokeResponse | AepProblemDetails>>;
  status(
    options: AepAuthenticatedServiceOptions
  ): Promise<AepServiceResponse<StatusResponseBody | AepProblemDetails>>;
}

export function createAepService(options: AepServiceOptions): AepService {
  const inspectDocument = buildInspectDocument(options);
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
        commandIdempotencyStore,
        store: enrollmentStore,
        ...(options.clock === undefined ? {} : { clock: options.clock }),
        policy: enrollmentPolicy,
        ...(commandOptions.idempotencyKey === undefined
          ? {}
          : { idempotencyKey: commandOptions.idempotencyKey })
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
        store: enrollmentStore,
        ...(commandOptions.idempotencyKey === undefined
          ? {}
          : { idempotencyKey: commandOptions.idempotencyKey })
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
        store: enrollmentStore,
        ...(commandOptions.idempotencyKey === undefined
          ? {}
          : { idempotencyKey: commandOptions.idempotencyKey })
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

  const grantTypeConfig = Object.fromEntries(
    grantTypes
      .filter((definition) => definition.config !== undefined)
      .map((definition) => [definition.grantType, definition.config])
  );

  const document: InspectDocument = {
    aep_version: AEP_VERSION,
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
      endpoint_base: options.endpointBase ?? DEFAULT_HTTP_ENDPOINT_BASE
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

export function oauthBearerGrantType(config?: Record<string, unknown>): AepGrantTypeDefinition {
  return grantType(AEP_BUILT_IN_GRANT_TYPES[0], config);
}

export function apiKeyGrantType(config?: Record<string, unknown>): AepGrantTypeDefinition {
  return grantType(AEP_BUILT_IN_GRANT_TYPES[1], config);
}

export function basicGrantType(config?: Record<string, unknown>): AepGrantTypeDefinition {
  return grantType(AEP_BUILT_IN_GRANT_TYPES[2], config);
}

export function grantType(
  grantType: AepGrantType,
  config?: Record<string, unknown>,
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
      idempotencyLookupKey(record.agentDid, record.command, record.idempotencyKey),
      cloneIdempotencyResponseRecord(record)
    )
  );

  return {
    async executeIdempotentCommand(input, execute) {
      const key = idempotencyLookupKey(input.agentDid, input.command, input.idempotencyKey);

      for (;;) {
        const existing = idempotency.get(key);

        if (existing !== undefined) {
          if (existing.requestHash !== input.requestHash) {
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
    const key = await resolveDidWebPublicKey({
      did: issuer,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      ...(typeof untrusted.header["kid"] === "string" ? { kid: untrusted.header["kid"] } : {})
    });

    return verifyClientAssertionJwt(clientAssertion, {
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
    const response = await fetchImpl(options.endpoint, {
      body: JSON.stringify({
        client_assertion: clientAssertion,
        op: context.command,
        service_did: context.serviceDid
      }),
      headers: {
        Accept: AEP_MEDIA_TYPE,
        ...(options.authorization === undefined ? {} : { Authorization: options.authorization }),
        "Content-Type": AEP_MEDIA_TYPE
      },
      method: "POST"
    });

    if (!response.ok) {
      throw new Error(`AEP hosted verification failed with HTTP ${response.status}.`);
    }

    const verification = parseHostedPlatformVerificationResponse(await response.json());
    const claims = parseClientAssertionClaims(decodeJwtUnverified(clientAssertion).payload);

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
  service: Pick<AepService, "status">,
  authorization: string | null | undefined
): Promise<AepServiceResponse<StatusResponseBody | AepProblemDetails>> {
  return service.status({
    clientAssertion: clientAssertionFromAepAuthorization(authorization)
  });
}

export function isActiveProtectedResourceAuthentication(result: AepServiceResponse): boolean {
  return isRecord(result.body) && result.body["status"] === "active";
}

export function createInMemoryServiceCredentialStore(
  records: AepServiceCredentialRecord[] = []
): AepServiceCredentialStore {
  const credentials = new Map<string, AepServiceCredentialRecord>();

  records.forEach((record) =>
    credentials.set(serviceCredentialKey(record), cloneCredential(record))
  );

  return {
    findCredential(agentDid, grantTypeName, credentialId) {
      const record = credentials.get(
        serviceCredentialLookupKey(agentDid, grantTypeName, credentialId)
      );

      return record === undefined ? undefined : cloneCredential(record);
    },
    listCredentials(agentDid, grantTypeName) {
      return [...credentials.values()]
        .filter(
          (record) =>
            record.agentDid === agentDid &&
            (grantTypeName === undefined || record.grantType === grantTypeName)
        )
        .map(cloneCredential);
    },
    revokeCredential(agentDid, grantTypeName, credentialId, revokedAt) {
      const key = serviceCredentialLookupKey(agentDid, grantTypeName, credentialId);
      const record = credentials.get(key);

      if (record !== undefined) {
        credentials.set(key, {
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
      credentials.set(serviceCredentialKey(parsed), cloneCredential(parsed));
      return cloneCredential(parsed);
    }
  };
}

export interface HandleEnrollRequestOptions {
  clock?: () => Date;
  commandIdempotencyStore?: AepCommandIdempotencyStore;
  idempotencyKey?: string;
  policy: AepEnrollmentPolicy;
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

  if (options.idempotencyKey !== undefined && options.idempotencyKey !== parsed.idempotency_key) {
    return problem("invalid_request", "Invalid request", 400);
  }

  return withIdempotency(
    "enroll",
    parsed.agent_did,
    parsed.idempotency_key,
    parsed,
    options.commandIdempotencyStore,
    async () => {
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
  owner_action_required: "true" | "false";
  requirements_pending: string[];
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
  idempotencyKey?: string;
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

  const enrollment = await options.store.findEnrollment(options.agentDid);

  if (enrollment === undefined) {
    return problem("not_recognized", "Not recognized", 401);
  }

  if (enrollment.status !== "active") {
    return problem("verification_pending", "Verification pending", 403);
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
  idempotencyKey?: string;
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
  command: AuthenticatedServiceCommand,
  commandOptions: AepAuthenticatedServiceOptions,
  options: AuthenticateClientAssertionOptions
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
        serviceDid: options.serviceDid,
        signingAlgorithms: options.signingAlgorithms
      })
    );
  } catch {
    return notRecognized();
  }

  if (!validateClientAssertionClaimsForCommand(claims, command, options)) {
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
  command: AuthenticatedServiceCommand,
  options: AuthenticateClientAssertionOptions
): boolean {
  const clock = options.config?.clock ?? (() => new Date());
  const clockSkewSeconds = options.config?.clockSkewSeconds ?? 30;
  const maxTtlSeconds = options.config?.maxTtlSeconds ?? 300;
  const now = Math.floor(clock().getTime() / 1000);

  return (
    claims.iss === claims.sub &&
    claims.aud === options.serviceDid &&
    claims.op === command &&
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
  return grantType(grantTypeName, options.config, {
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
    }
  });
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
      : {})
  };
}

function statusResponseFromRecord(record: AepEnrollmentRecord): StatusResponseBody {
  return {
    owner_action_required: record.ownerActionRequired ? "true" : "false",
    requirements_pending: [...record.requirementsPending],
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
    status
  };
}

function notRecognized(): AuthenticateClientAssertionResult {
  return {
    ok: false,
    response: problem("not_recognized", "Not recognized", 401)
  };
}

async function withIdempotency<TBody>(
  command: AuthenticatedServiceCommand,
  agentDid: string,
  idempotencyKey: string | undefined,
  request: unknown,
  store: AepCommandIdempotencyStore | undefined,
  execute: () => Promise<AepServiceResponse<TBody>>
): Promise<AepServiceResponse<TBody | AepProblemDetails>> {
  if (idempotencyKey === undefined || store === undefined) {
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

function idempotencyLookupKey(
  agentDid: string,
  command: AuthenticatedServiceCommand,
  idempotencyKey: string
): string {
  return command === "enroll"
    ? `${command}\u0000${idempotencyKey}`
    : `${agentDid}\u0000${command}\u0000${idempotencyKey}`;
}

function cloneEnrollmentRecord(record: AepEnrollmentRecord): AepEnrollmentRecord {
  return {
    ...record,
    claims: structuredClone(record.claims),
    requirementsPending: [...record.requirementsPending]
  };
}

function cloneIdempotencyResponseRecord(
  record: AepCommandIdempotencyRecord
): AepCommandIdempotencyRecord {
  return {
    ...record,
    body: structuredClone(record.body)
  };
}

function serviceCredentialLookupKey(
  agentDid: string,
  grantTypeName: AepBuiltInGrantType,
  credentialId: string
): string {
  return `${agentDid}\u0000${grantTypeName}\u0000${credentialId}`;
}

function serviceCredentialKey(record: AepServiceCredentialRecord): string {
  return serviceCredentialLookupKey(record.agentDid, record.grantType, record.credentialId);
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
  return `json:${stableStringify(request)}`;
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
