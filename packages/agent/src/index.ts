import {
  AEP_AUTH_SCHEME,
  AEP_AUTHORIZATION_HEADER,
  AEP_ASSERTION_OPERATIONS,
  AEP_BUILT_IN_GRANT_TYPES,
  AEP_MEDIA_TYPE,
  AEP_SIGNING_ALGORITHMS,
  AEP_WELL_KNOWN_PATH,
  AepAuthorizationCarrierError,
  commandPathFromInspect,
  missingAepRequiredClaimNames,
  parseAepClaimValues,
  parseBuiltInGrantResponse,
  parseClientAssertionClaims,
  parseEnrollResponse,
  parseGrantRequest,
  parseInspectDocument,
  parseProblemDetails,
  parseRevokeRequest,
  parseRevokeResponse,
  parseStatusResponse,
  renderProtectedResourceAuthorization,
  signClientAssertionJwt
} from "@aep-foundation/core";
import {
  createPlatformProvisionRequest,
  createPlatformSignRequest
} from "@aep-foundation/platform";
import type {
  AepBuiltInGrantResponse,
  AepAuthenticatedCommand,
  AepAssertionOperation,
  AepAuthenticationMethod,
  AepClaimName,
  AepClaimValues,
  AepClientAssertionClaims,
  AepHttpCommand,
  AepGrantType,
  AepProblemDetails,
  AepProtectedResourceAuthorizationCarrier,
  AepSigningAlgorithm,
  AepImportableJoseKey,
  ApiKeyGrantResponse,
  BasicGrantResponse,
  EnrollResponse,
  InspectDocument,
  OAuthBearerGrantResponse,
  RevokeRequest,
  RevokeResponse,
  StatusResponse
} from "@aep-foundation/core";
import type {
  PlatformAgentIdentity,
  PlatformAgentIdentityListResponse,
  PlatformDiscoveryDocument,
  PlatformSignResponse
} from "@aep-foundation/platform";
import {
  createInMemoryPublicDocumentCache,
  fetchAepPublicDocument,
  interpretAepOpenApiOperation
} from "./public-documents.js";
import type { AepOpenApiOperationPolicy, AepPublicDocumentCache } from "./public-documents.js";

export * from "./public-documents.js";

export type Awaitable<T> = T | Promise<T>;

export type PlatformAuthenticationHeaders = Record<string, string>;
export type PlatformAuthenticationHeadersProvider = () => Awaitable<PlatformAuthenticationHeaders>;
export type PlatformAuthenticationHeadersInput =
  PlatformAuthenticationHeaders | PlatformAuthenticationHeadersProvider;

export interface AepClientAssertionSignerContext {
  command: AepAssertionOperation;
  serviceDid: string;
  signingAlgorithms: AepSigningAlgorithm[];
  platformContext?: Record<string, unknown>;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

export type AepClientAssertionSignResult =
  | { status: "completed"; clientAssertion: string; platformContext?: Record<string, unknown> }
  | { status: "pending"; platformContext?: Record<string, unknown>; retryAfterSeconds: number };

export type AepClientAssertionSigner = (
  claims: AepClientAssertionClaims,
  context: AepClientAssertionSignerContext
) => Awaitable<string | AepClientAssertionSignResult>;

export type AepCompletedClientAssertionSignResult = Extract<
  AepClientAssertionSignResult,
  { status: "completed" }
>;
export type AepPendingClientAssertionSignResult = Extract<
  AepClientAssertionSignResult,
  { status: "pending" }
>;

export interface AepPendingSignResolverInput {
  claims: AepClientAssertionClaims;
  context: AepClientAssertionSignerContext;
  pending: AepPendingClientAssertionSignResult;
  signal?: AbortSignal;
  continueSign(): Promise<AepClientAssertionSignResult>;
}

export type AepPendingSignResolver = (
  input: AepPendingSignResolverInput
) => Awaitable<AepCompletedClientAssertionSignResult>;

export interface AepPlatformContextProviderInput {
  command: AepAssertionOperation;
  identity: AgentServiceIdentity;
  serviceDid: string;
  grantType?: AepGrantType;
  requestedScopes?: readonly string[];
  resource?: string;
}

export type AepPlatformContextProvider = (
  input: AepPlatformContextProviderInput
) => Awaitable<Record<string, unknown> | undefined>;

export interface AepAgentOptions {
  assertionClock?: () => Date;
  assertionJti?: () => string;
  assertionTtlSeconds?: number;
  credentialStore?: AgentCredentialStore;
  identityProvider: AgentIdentityProvider;
  identityStore?: AgentIdentityStore;
  idempotencyKeys?: AgentIdempotencyKeyProvider;
  inspectCache?: AgentInspectCache;
  publicDocumentCache?: AepPublicDocumentCache;
  pendingSignResolver?: AepPendingSignResolver;
  platformContextProvider?: AepPlatformContextProvider;
}

export interface InspectServiceOptions {
  serviceUrl: string | URL;
  signal?: AbortSignal;
  maxResponseBytes?: number;
  inspectCache?: AgentInspectCache;
  publicDocumentCache?: AepPublicDocumentCache;
  clock?: () => Date;
}

export interface InspectServiceResult {
  document: InspectDocument;
  inspectUrl: URL;
  finalUrl?: URL;
  commandUrl(command: AepHttpCommand): URL;
  cacheControl?: string;
  etag?: string;
  lastModified?: string;
}

export interface InspectOpenApiPolicyOptions {
  inspect: InspectServiceResult;
  method?: string;
  publicDocumentCache?: AepPublicDocumentCache;
  signal?: AbortSignal;
  url: string | URL;
  maxResponseBytes?: number;
}

export async function inspectOpenApiPolicy(
  options: InspectOpenApiPolicyOptions
): Promise<AepOpenApiOperationPolicy> {
  const advertisement = options.inspect.document.http.openapi;
  if (advertisement === undefined)
    return { source: "openapi", state: "fallback", methods: [], freshness: "fetched" };
  const base = options.inspect.finalUrl ?? options.inspect.inspectUrl;
  const fetched = await fetchAepPublicDocument({
    accept: "application/vnd.oai.openapi+json;version=3.1, application/json",
    acceptedMediaTypes: ["application/vnd.oai.openapi+json", "application/json"],
    ...(options.publicDocumentCache === undefined ? {} : { cache: options.publicDocumentCache }),
    ...(options.maxResponseBytes === undefined
      ? {}
      : { maxResponseBytes: options.maxResponseBytes }),
    namespace: "openapi",
    parse: (value) => value,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    url: new URL(advertisement.url, base)
  });
  return interpretAepOpenApiOperation(
    fetched.value,
    {
      ...(options.method === undefined ? {} : { method: options.method }),
      trailingSlash: advertisement.path_matching.trailing_slash,
      url: options.url
    },
    fetched.freshness
  );
}

export interface DiscoverPlatformOptions {
  platformUrl: string | URL;
  publicDocumentCache?: AepPublicDocumentCache;
  signal?: AbortSignal;
}

export interface DiscoverPlatformResult {
  document: PlatformDiscoveryDocument;
  discoveryUrl: URL;
  endpointUrl(endpoint: keyof PlatformDiscoveryDocument["endpoints"]): URL;
  freshness?: "fresh" | "revalidated" | "fetched";
}

export interface ProvisionPlatformIdentityOptions {
  authenticationHeaders?: PlatformAuthenticationHeadersInput;
  authorization?: string;
  discovery?: DiscoverPlatformResult;
  idempotencyKey: string;
  platformUrl: string | URL;
  serviceDid: string;
  publicDocumentCache?: AepPublicDocumentCache;
}

export type ProvisionPlatformIdentityResult = AepCommandResult<PlatformAgentIdentity>;

export interface ListPlatformIdentitiesOptions {
  authenticationHeaders?: PlatformAuthenticationHeadersInput;
  authorization?: string;
  descending?: boolean;
  discovery?: DiscoverPlatformResult;
  limit?: number;
  offset?: number;
  platformUrl: string | URL;
  serviceDid?: string;
  status?: PlatformAgentIdentity["status"];
  publicDocumentCache?: AepPublicDocumentCache;
}

export type ListPlatformIdentitiesResult = AepCommandResult<PlatformAgentIdentityListResponse>;

export interface PlatformDelegatedSignerOptions {
  authenticationHeaders?: PlatformAuthenticationHeadersInput;
  authorization?: string;
  discovery?: DiscoverPlatformResult;
  identity: PlatformAgentIdentity;
  platformUrl: string | URL;
  idempotencyKey?: string | (() => string);
  publicDocumentCache?: AepPublicDocumentCache;
}

export interface AepCommandResult<TBody> {
  body: TBody;
  commandUrl: URL;
  status: number;
}

export interface AepCommandOptions {
  agentDid?: string;
  assertionClock?: () => Date;
  assertionJti?: () => string;
  assertionTtlSeconds?: number;
  clientAssertion?: string;
  clientAssertionSigner?: AepClientAssertionSigner;
  inspect?: InspectServiceResult;
  pendingSignResolver?: AepPendingSignResolver;
  platformContext?: Record<string, unknown>;
  serviceUrl: string | URL;
  signal?: AbortSignal;
}

export interface EnrollServiceOptions extends AepCommandOptions {
  agentDid: string;
  claims?: AepClaimValues;
  idempotencyKey: string;
}

export type EnrollServiceResult = AepCommandResult<EnrollResponse>;

export interface GrantServiceOptions extends AepCommandOptions {
  grantType: AepGrantType;
  idempotencyKey: string;
  parameters?: Record<string, unknown>;
  requestedScopes?: string[];
}

export type GrantServiceResult = AepCommandResult<
  AepBuiltInGrantResponse | Record<string, unknown>
>;

type RevokeServiceSelector =
  | {
      allGrantTypes: true;
      credentialId?: never;
      grantType?: never;
    }
  | {
      allGrantTypes?: never;
      credentialId: string;
      grantType?: never;
    }
  | {
      allGrantTypes?: never;
      credentialId?: never;
      grantType: AepGrantType;
    };

export type RevokeServiceOptions = AepCommandOptions &
  RevokeServiceSelector & {
    idempotencyKey: string;
    parameters?: Record<string, unknown>;
  };

export type RevokeServiceResult = AepCommandResult<RevokeResponse>;
export type AgentRevokeServiceOptions = RevokeServiceOptions;

export type StatusServiceOptions = AepCommandOptions;
export type StatusServiceResult = AepCommandResult<StatusResponse>;

export interface BuildClientAssertionClaimsOptions {
  agentDid: string;
  command: AepAssertionOperation;
  clock?: () => Date;
  jti?: string | (() => string);
  serviceDid: string;
  resource?: string;
  ttlSeconds?: number;
}

export interface SignClientAssertionOptions extends BuildClientAssertionClaimsOptions {
  idempotencyKey?: string;
  pendingSignResolver?: AepPendingSignResolver;
  platformContext?: Record<string, unknown>;
  signal?: AbortSignal;
  signer: AepClientAssertionSigner;
  signingAlgorithms?: AepSigningAlgorithm[];
}

export interface JwtClientAssertionSignerOptions {
  alg?: AepSigningAlgorithm;
  key: AepImportableJoseKey;
  kid?: string;
  typ?: string;
}

export interface ClientAssertionAuthenticationHeadersOptions extends Omit<
  SignClientAssertionOptions,
  "command" | "serviceDid" | "signingAlgorithms"
> {
  carrier?: AepProtectedResourceAuthorizationCarrier;
  command?: AepAssertionOperation;
  inspect?: InspectDocument | InspectServiceResult;
  serviceDid?: string;
  resource?: string;
  signingAlgorithms?: AepSigningAlgorithm[];
}

export type ProtectedResourceAuthenticationHeadersOptions =
  | {
      carrier?: AepProtectedResourceAuthorizationCarrier;
      credential: AepBuiltInGrantResponse;
    }
  | ClientAssertionAuthenticationHeadersOptions;

export interface SelectGrantTypeOptions {
  preferredGrantTypes?: AepGrantType[];
}

export interface AepSessionCredentialRecord {
  credential: AepBuiltInGrantResponse | Record<string, unknown>;
  credentialId: string;
  expiresAt?: string;
  grantType: AepGrantType;
  issuedAt: string;
  serviceDid: string;
  serviceUrl?: string;
}

export type AgentCredentialRecord = AepSessionCredentialRecord;

export interface AgentCredentialStore {
  deleteCredential(serviceDid: string, credentialId: string): Awaitable<void>;
  findCredential(
    serviceDid: string,
    credentialId: string
  ): Awaitable<AgentCredentialRecord | undefined>;
  findUsableCredential(
    serviceDid: string,
    now?: Date
  ): Awaitable<AgentCredentialRecord | undefined>;
  listCredentials(serviceDid: string): Awaitable<AgentCredentialRecord[]>;
  saveCredential(record: AgentCredentialRecord): Awaitable<AgentCredentialRecord>;
}

export type AepSessionCredentialStore = AgentCredentialStore;

export interface AgentServiceIdentity {
  agentDid: string;
  identityKind: "platform-hosted" | "sovereign";
  metadata?: Record<string, unknown>;
  serviceDid: string;
  signingAlgorithms: AepSigningAlgorithm[];
}

export interface AgentIdentityProviderGetOrCreateInput {
  inspect: InspectDocument;
  serviceDid: string;
  serviceUrl: string;
}

export interface AgentIdentityProvider {
  getOrCreateIdentity(
    input: AgentIdentityProviderGetOrCreateInput
  ): Awaitable<AgentServiceIdentity>;
  signerFor(identity: AgentServiceIdentity): Awaitable<AepClientAssertionSigner>;
}

export interface PlatformIdentityProvider extends AgentIdentityProvider {
  findIdentityByServiceDid(serviceDid: string): Awaitable<AgentServiceIdentity | undefined>;
}

export interface AgentIdentityStore {
  findByServiceDid(serviceDid: string): Awaitable<AgentServiceIdentity | undefined>;
  saveIdentity(identity: AgentServiceIdentity): Awaitable<AgentServiceIdentity>;
}

export interface AgentOperationKey {
  command: AepAuthenticatedCommand;
  credentialId?: string;
  grantType?: AepGrantType;
  serviceDid: string;
  serviceUrl: string;
}

export interface AgentIdempotencyKeyProvider {
  createKey(operation: AgentOperationKey): Awaitable<string>;
}

export interface CachedInspectServiceResult extends InspectServiceResult {
  cachedAt: string;
}

export interface AgentInspectCache {
  get(serviceUrl: string): Awaitable<CachedInspectServiceResult | undefined>;
  delete(serviceUrl: string): Awaitable<void>;
  set(serviceUrl: string, result: CachedInspectServiceResult): Awaitable<void>;
}

export interface CreatePlatformIdentityProviderOptions {
  authenticationHeaders?: PlatformAuthenticationHeadersInput;
  authorization?: string;
  idempotencyKey?: string | ((input: AgentIdentityProviderGetOrCreateInput) => string);
  platformUrl: string | URL;
  publicDocumentCache?: AepPublicDocumentCache;
}

export interface AgentServiceSessionOptions {
  serviceUrl: string | URL;
}

export interface AgentEnrollSessionOptions {
  claims?: AepClaimValues;
  idempotencyKey?: string;
}

export interface AgentGrantSessionOptions {
  grantType?: AepGrantType;
  idempotencyKey?: string;
  parameters?: Record<string, unknown>;
  preferredGrantTypes?: AepGrantType[];
  requestedScopes?: string[];
  signal?: AbortSignal;
}

export type AgentRevokeSessionOptions = RevokeServiceSelector & {
  idempotencyKey?: string;
  parameters?: Record<string, unknown>;
};

export interface AgentAuthenticationHeadersOptions {
  carrier?: AepProtectedResourceAuthorizationCarrier;
  preferCredential?: boolean;
  credentialId?: string;
  grantType?: AepGrantType;
  resource?: string;
  signal?: AbortSignal;
}

export interface AepServiceSession {
  authenticationHeaders(
    options?: AgentAuthenticationHeadersOptions
  ): Promise<Record<string, string>>;
  enroll(options?: AgentEnrollSessionOptions): Promise<EnrollServiceResult>;
  forgetCredential(credentialId: string): Promise<void>;
  grant(options?: AgentGrantSessionOptions): Promise<GrantServiceResult>;
  identity(): Promise<AgentServiceIdentity>;
  inspect(): Promise<InspectServiceResult>;
  openApiPolicy(options: {
    method?: string;
    signal?: AbortSignal;
    url: string | URL;
  }): Promise<AepOpenApiOperationPolicy>;
  revoke(options: AgentRevokeSessionOptions): Promise<RevokeServiceResult>;
  status(): Promise<StatusServiceResult>;
}

export interface ProbeProtectedResourceOptions {
  body?: RequestInit["body"];
  headers?: RequestInit["headers"];
  method?: string;
  signal?: AbortSignal;
  url: string | URL;
}

export interface AepAuthenticationChallenge {
  inspect: URL;
  reason?: string;
  serviceDid: string;
}

export type ProtectedResourceProbeClassification =
  "success" | "aep-challenge" | "unrelated-authentication" | "http-response";

export interface ProbeProtectedResourceResult {
  challenge?: AepAuthenticationChallenge;
  classification: ProtectedResourceProbeClassification;
  response: Response;
}

export interface FetchProtectedResourceOptions extends ProbeProtectedResourceOptions {
  additionalAuthenticationHeaders?: Readonly<Record<string, string>>;
  agent: AepAgent;
  credentialId?: string;
  grantType?: AepGrantType;
  carrier?: AepProtectedResourceAuthorizationCarrier;
  maxRedirects?: number;
  timeoutMs?: number;
}

export type FetchLike = (input: URL | string, init?: RequestInit) => Promise<ResponseLike>;

export interface ResponseLike {
  ok: boolean;
  status: number;
  statusText?: string;
  headers: HeadersLike;
  json(): Promise<unknown>;
  text?(): Promise<string>;
  body?: ReadableStream<Uint8Array> | null;
  url?: string;
}

export interface HeadersLike {
  get(name: string): string | null;
}

export type AepInspectErrorCode =
  | "aborted"
  | "http_error"
  | "invalid_json"
  | "invalid_media_type"
  | "invalid_redirect"
  | "response_too_large"
  | "validation_failed";
export class AepInspectError extends Error {
  readonly code: AepInspectErrorCode;
  readonly status?: number;

  constructor(message: string, code: AepInspectErrorCode = "http_error", status?: number) {
    super(message);
    this.name = "AepInspectError";
    this.code = code;

    if (status !== undefined) {
      this.status = status;
    }
  }
}

export class AepServiceReferenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AepServiceReferenceError";
  }
}

export function resolveServiceReference(reference: string | URL): URL {
  const raw = String(reference).trim();
  let url: URL;
  try {
    if (raw.startsWith("did:web:")) {
      const method = raw.slice("did:web:".length).split(":");
      if (method.length === 0 || method[0] === "") throw new Error();
      const host = decodeURIComponent(method[0] ?? "");
      url = new URL(`https://${host}`);
    } else {
      url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `https://${raw}`);
    }
  } catch {
    throw new AepServiceReferenceError("Invalid AEP Service reference.");
  }
  if (url.username || url.password)
    throw new AepServiceReferenceError("Service references must not contain credentials.");
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]" ||
    url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
    throw new AepServiceReferenceError(
      "Service references require HTTPS except for exact loopback hosts."
    );
  return new URL(url.origin);
}

export class AepCommandError extends Error {
  readonly problem?: AepProblemDetails;
  readonly status: number;

  constructor(message: string, status: number, problem?: AepProblemDetails) {
    super(message);
    this.name = "AepCommandError";
    this.status = status;

    if (problem !== undefined) {
      this.problem = problem;
    }
  }
}

export class AepClaimRequirementsError extends Error {
  readonly missingRequiredClaimNames: AepClaimName[];

  constructor(missingRequiredClaimNames: readonly AepClaimName[]) {
    super(`Cannot satisfy required AEP Claim Names: ${missingRequiredClaimNames.join(", ")}.`);
    this.name = "AepClaimRequirementsError";
    this.missingRequiredClaimNames = [...missingRequiredClaimNames];
  }
}

export interface AepAgent {
  serviceSession(options: AgentServiceSessionOptions): AepServiceSession;
}

export function createAepAgent(options: AepAgentOptions): AepAgent {
  const identityStore = options.identityStore ?? createInMemoryAgentIdentityStore();
  const credentialStore = options.credentialStore ?? createInMemorySessionCredentialStore();
  const idempotencyKeys = options.idempotencyKeys ?? createRandomIdempotencyKeyProvider();
  const inspectCache = options.inspectCache ?? createInMemoryInspectCache();
  const publicDocumentCache = options.publicDocumentCache ?? createInMemoryPublicDocumentCache();
  const assertionOptions = assertionOptionsWithDefinedValues(options);
  const grantFlights = new Map<string, Promise<GrantServiceResult>>();

  return {
    serviceSession: (sessionOptions) =>
      createAepServiceSession({
        ...assertionOptions,
        credentialStore,
        idempotencyKeys,
        identityProvider: options.identityProvider,
        identityStore,
        inspectCache,
        publicDocumentCache,
        ...(options.pendingSignResolver === undefined
          ? {}
          : { pendingSignResolver: options.pendingSignResolver }),
        ...(options.platformContextProvider === undefined
          ? {}
          : { platformContextProvider: options.platformContextProvider }),
        grantFlights,
        serviceUrl: sessionOptions.serviceUrl
      })
  };
}

interface AepServiceSessionState {
  assertionClock?: () => Date;
  assertionJti?: () => string;
  assertionTtlSeconds?: number;
  credentialStore: AgentCredentialStore;
  idempotencyKeys: AgentIdempotencyKeyProvider;
  identityProvider: AgentIdentityProvider;
  identityStore: AgentIdentityStore;
  inspectCache: AgentInspectCache;
  publicDocumentCache: AepPublicDocumentCache;
  pendingSignResolver?: AepPendingSignResolver;
  platformContextProvider?: AepPlatformContextProvider;
  grantFlights: Map<string, Promise<GrantServiceResult>>;
  serviceUrl: string | URL;
}

function createAepServiceSession(state: AepServiceSessionState): AepServiceSession {
  const serviceUrl = normalizeServiceUrl(state.serviceUrl);
  const serviceUrlString = String(serviceUrl);
  let inspectPromise: Promise<InspectServiceResult> | undefined;
  let identityPromise: Promise<AgentServiceIdentity> | undefined;
  let signerPromise: Promise<AepClientAssertionSigner> | undefined;
  let authoritativeActiveEnrollment = false;

  const inspectOnce = async (): Promise<InspectServiceResult> => {
    if (inspectPromise !== undefined) {
      return inspectPromise;
    }

    inspectPromise = (async () => {
      return inspectService({
        inspectCache: state.inspectCache,
        publicDocumentCache: state.publicDocumentCache,
        serviceUrl
      });
    })();

    return inspectPromise;
  };

  const identityOnce = async (): Promise<AgentServiceIdentity> => {
    if (identityPromise !== undefined) {
      return identityPromise;
    }

    identityPromise = (async () => {
      const inspected = await inspectOnce();
      const serviceDid = inspected.document.service.did;
      const existing = await state.identityStore.findByServiceDid(serviceDid);

      if (existing !== undefined) {
        return existing;
      }

      const created = await state.identityProvider.getOrCreateIdentity({
        inspect: inspected.document,
        serviceDid,
        serviceUrl: serviceUrlString
      });

      return state.identityStore.saveIdentity(created);
    })();

    return identityPromise;
  };

  const signerOnce = async (): Promise<AepClientAssertionSigner> => {
    if (signerPromise !== undefined) {
      return signerPromise;
    }

    signerPromise = Promise.resolve(state.identityProvider.signerFor(await identityOnce()));
    return signerPromise;
  };

  const existingIdentityOnce = async (): Promise<AgentServiceIdentity> => {
    const inspected = await inspectOnce();
    const serviceDid = inspected.document.service.did;
    const stored = await state.identityStore.findByServiceDid(serviceDid);
    if (stored !== undefined) return stored;
    if (isPlatformIdentityProvider(state.identityProvider)) {
      const recovered = await state.identityProvider.findIdentityByServiceDid(serviceDid);
      if (recovered !== undefined) return state.identityStore.saveIdentity(recovered);
    }
    throw new AepCommandError("Grant requires an existing enrolled identity.", 401, {
      type: "urn:aep:error:not_recognized",
      title: "Not recognized",
      status: 401,
      code: "not_recognized"
    });
  };

  const commandOptions = async (): Promise<
    Pick<EnrollServiceOptions, "agentDid" | "clientAssertionSigner" | "inspect" | "serviceUrl">
  > => {
    const inspected = await inspectOnce();
    const identity = await identityOnce();
    const signer = await signerOnce();

    return {
      agentDid: identity.agentDid,
      clientAssertionSigner: signer,
      inspect: inspected,
      serviceUrl
    };
  };

  const assertionOptions = (): Pick<
    AepCommandOptions,
    "assertionClock" | "assertionJti" | "assertionTtlSeconds"
  > => ({
    ...(state.assertionClock === undefined ? {} : { assertionClock: state.assertionClock }),
    ...(state.assertionJti === undefined ? {} : { assertionJti: state.assertionJti }),
    ...(state.assertionTtlSeconds === undefined
      ? {}
      : { assertionTtlSeconds: state.assertionTtlSeconds })
  });

  const idempotencyKey = async (
    operation: Omit<AgentOperationKey, "serviceDid" | "serviceUrl">
  ): Promise<string> => {
    const inspected = await inspectOnce();

    return state.idempotencyKeys.createKey({
      ...operation,
      serviceDid: inspected.document.service.did,
      serviceUrl: serviceUrlString
    });
  };

  return {
    async authenticationHeaders(options = {}) {
      const inspected = await inspectOnce();

      if (options.preferCredential !== false) {
        const credential =
          options.credentialId === undefined
            ? await findCompatibleCredential(
                state.credentialStore,
                inspected.document.service.did,
                options.grantType,
                inspected.document.authentication?.methods
              )
            : await state.credentialStore.findCredential(
                inspected.document.service.did,
                options.credentialId
              );

        if (credential !== undefined) {
          return protectedResourceAuthenticationHeaders({
            ...(options.carrier === undefined ? {} : { carrier: options.carrier }),
            credential: parseBuiltInGrantResponse(credential.grantType, credential.credential)
          });
        }
      }

      if (
        inspected.document.authentication !== undefined &&
        !inspected.document.authentication.methods.includes("aep-jwt")
      ) {
        throw new TypeError("Service does not advertise AEP JWT authentication.");
      }

      const identity = await identityOnce();
      const signer = await signerOnce();

      return protectedResourceAuthenticationHeaders({
        agentDid: identity.agentDid,
        ...(options.carrier === undefined ? {} : { carrier: options.carrier }),
        inspect: inspected,
        command: options.resource === undefined ? "status" : "authenticate",
        ...(state.assertionClock === undefined ? {} : { clock: state.assertionClock }),
        ...(state.assertionJti === undefined ? {} : { jti: state.assertionJti }),
        signer,
        ...(state.pendingSignResolver === undefined
          ? {}
          : { pendingSignResolver: state.pendingSignResolver }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(options.resource === undefined ? {} : { resource: options.resource }),
        ...(state.assertionTtlSeconds === undefined
          ? {}
          : { ttlSeconds: state.assertionTtlSeconds })
      });
    },
    async forgetCredential(credentialId) {
      const inspected = await inspectOnce();
      await state.credentialStore.deleteCredential(inspected.document.service.did, credentialId);
    },
    async enroll(options = {}) {
      const result = await enrollService({
        ...(await commandOptions()),
        ...assertionOptions(),
        ...(options.claims === undefined ? {} : { claims: options.claims }),
        idempotencyKey: options.idempotencyKey ?? (await idempotencyKey({ command: "enroll" }))
      });
      authoritativeActiveEnrollment = result.body.status === "active";
      return result;
    },
    async grant(options = {}) {
      const inspected = await inspectOnce();
      const grantType =
        options.grantType ??
        selectGrantType(inspected, {
          ...(options.preferredGrantTypes === undefined
            ? {}
            : { preferredGrantTypes: options.preferredGrantTypes })
        });
      const flightKey = `${inspected.document.service.did}\u0000${grantType}\u0000${[...(options.requestedScopes ?? [])].sort().join(" ")}`;
      const existingFlight = state.grantFlights.get(flightKey);
      if (existingFlight !== undefined) return existingFlight;
      const flight = (async () => {
        const identity = await existingIdentityOnce();
        const signer = await state.identityProvider.signerFor(identity);
        if (!authoritativeActiveEnrollment) {
          const status = await statusService({
            ...assertionOptions(),
            agentDid: identity.agentDid,
            clientAssertionSigner: signer,
            inspect: inspected,
            serviceUrl,
            ...(options.signal === undefined ? {} : { signal: options.signal })
          });
          authoritativeActiveEnrollment = status.body.status === "active";
          if (!authoritativeActiveEnrollment)
            throw new AepCommandError("Grant requires active enrollment.", 401, {
              type: "urn:aep:error:not_recognized",
              title: "Not recognized",
              status: 401,
              code: "not_recognized"
            });
        }
        const platformContext =
          state.platformContextProvider === undefined
            ? undefined
            : await state.platformContextProvider({
                command: "grant",
                grantType,
                identity,
                ...(options.requestedScopes === undefined
                  ? {}
                  : { requestedScopes: [...options.requestedScopes] }),
                serviceDid: inspected.document.service.did
              });
        return grantService({
          ...assertionOptions(),
          agentDid: identity.agentDid,
          clientAssertionSigner: signer,
          inspect: inspected,
          serviceUrl,
          grantType,
          ...(platformContext === undefined ? {} : { platformContext }),
          ...(state.pendingSignResolver === undefined
            ? {}
            : { pendingSignResolver: state.pendingSignResolver }),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
          idempotencyKey:
            options.idempotencyKey ?? (await idempotencyKey({ command: "grant", grantType })),
          ...(options.parameters === undefined ? {} : { parameters: options.parameters }),
          ...(options.requestedScopes === undefined
            ? {}
            : { requestedScopes: options.requestedScopes })
        });
      })();
      state.grantFlights.set(flightKey, flight);
      let result: GrantServiceResult;
      try {
        result = await flight;
      } finally {
        state.grantFlights.delete(flightKey);
      }

      await state.credentialStore.saveCredential(
        sessionCredentialRecordFromGrantResult(result, {
          grantType,
          inspect: inspected,
          serviceUrl
        })
      );

      return result;
    },
    identity: identityOnce,
    inspect: inspectOnce,
    async openApiPolicy(options) {
      return inspectOpenApiPolicy({
        inspect: await inspectOnce(),
        ...(options.method === undefined ? {} : { method: options.method }),
        publicDocumentCache: state.publicDocumentCache,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        url: options.url
      });
    },
    async revoke(options) {
      const selector = revokeSessionSelector(options);
      const result = await revokeService({
        ...(await commandOptions()),
        ...assertionOptions(),
        ...selector,
        idempotencyKey:
          options.idempotencyKey ??
          (await idempotencyKey({
            command: "revoke",
            ...("credentialId" in selector ? { credentialId: selector.credentialId } : {}),
            ...("grantType" in selector ? { grantType: selector.grantType } : {})
          })),
        ...(options.parameters === undefined ? {} : { parameters: options.parameters })
      });
      const inspected = await inspectOnce();

      if ("credentialId" in selector) {
        await state.credentialStore.deleteCredential(
          inspected.document.service.did,
          selector.credentialId
        );
      }

      return result;
    },
    async status() {
      const result = await statusService({
        ...(await commandOptions()),
        ...assertionOptions()
      });
      authoritativeActiveEnrollment = result.body.status === "active";
      return result;
    }
  };
}

function isPlatformIdentityProvider(
  provider: AgentIdentityProvider
): provider is PlatformIdentityProvider {
  return "findIdentityByServiceDid" in provider;
}

function revokeSessionSelector(options: AgentRevokeSessionOptions): RevokeServiceSelector {
  if (options.allGrantTypes === true) {
    return { allGrantTypes: true };
  }

  if (options.credentialId !== undefined) {
    return { credentialId: options.credentialId };
  }

  return { grantType: options.grantType };
}

export function buildClientAssertionClaims(
  options: BuildClientAssertionClaimsOptions
): AepClientAssertionClaims {
  if (!AEP_ASSERTION_OPERATIONS.includes(options.command)) {
    throw new TypeError(`Unsupported authenticated command: ${options.command}.`);
  }

  const now = Math.floor((options.clock ?? (() => new Date()))().getTime() / 1000);
  const ttlSeconds = options.ttlSeconds ?? 300;
  const jti = typeof options.jti === "function" ? options.jti() : (options.jti ?? randomJti());

  return parseClientAssertionClaims({
    aud: options.serviceDid,
    exp: now + ttlSeconds,
    iat: now,
    iss: options.agentDid,
    jti,
    op: options.command,
    ...(options.resource === undefined ? {} : { resource: String(options.resource) }),
    sub: options.agentDid
  });
}

export async function signClientAssertion(options: SignClientAssertionOptions): Promise<string> {
  const claims = buildClientAssertionClaims(options);
  const initialContext: AepClientAssertionSignerContext = {
    command: options.command,
    idempotencyKey: options.idempotencyKey ?? randomJti(),
    serviceDid: options.serviceDid,
    signingAlgorithms: [...(options.signingAlgorithms ?? AEP_SIGNING_ALGORITHMS)],
    ...(options.platformContext === undefined ? {} : { platformContext: options.platformContext }),
    ...(options.signal === undefined ? {} : { signal: options.signal })
  };
  throwIfAborted(options.signal);
  const result = await options.signer(claims, initialContext);
  if (typeof result === "string") return result;
  if (result.status === "completed") return result.clientAssertion;
  if (options.pendingSignResolver === undefined) throw new AepPendingSignError(result);

  const completionContext: AepClientAssertionSignerContext = {
    ...initialContext,
    idempotencyKey: randomJti(),
    ...(result.platformContext === undefined ? {} : { platformContext: result.platformContext })
  };
  const continueSign = async (): Promise<AepClientAssertionSignResult> => {
    throwIfAborted(options.signal);
    const continued = await options.signer(claims, completionContext);
    return typeof continued === "string"
      ? { status: "completed", clientAssertion: continued }
      : continued;
  };
  try {
    throwIfAborted(options.signal);
    const completed = await options.pendingSignResolver({
      claims,
      context: completionContext,
      pending: result,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      continueSign
    });
    throwIfAborted(options.signal);
    return completed.clientAssertion;
  } catch (error) {
    if (error instanceof AepPendingSignResolverError) throw error;
    if (options.signal?.aborted === true) {
      throw new AepPendingSignResolverError("Pending Sign resolution was aborted.", "aborted", {
        cause: error
      });
    }
    throw new AepPendingSignResolverError("Pending Sign resolution failed.", "resolver_failed", {
      cause: error
    });
  }
}

export class AepPendingSignError extends Error {
  readonly result: AepPendingClientAssertionSignResult;
  constructor(result: AepPendingClientAssertionSignResult) {
    super("Platform signing is pending.");
    this.name = "AepPendingSignError";
    this.result = result;
  }
}

export class AepPendingSignResolverError extends Error {
  readonly code: string;

  constructor(message: string, code: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AepPendingSignResolverError";
    this.code = code;
  }
}

export function createJwtClientAssertionSigner(
  options: JwtClientAssertionSignerOptions
): AepClientAssertionSigner {
  return (claims, context) =>
    signClientAssertionJwt(claims, {
      alg: options.alg ?? preferredSigningAlgorithm(context.signingAlgorithms),
      key: options.key,
      ...(options.kid === undefined ? {} : { kid: options.kid }),
      ...(options.typ === undefined ? {} : { typ: options.typ })
    });
}

export async function discoverPlatform(
  options: DiscoverPlatformOptions
): Promise<DiscoverPlatformResult> {
  const platformUrl = normalizePlatformUrl(options.platformUrl);
  const discoveryUrl = new URL("/.well-known/aep-platform", platformUrl);
  const fetched = await fetchAepPublicDocument({
    accept: AEP_MEDIA_TYPE,
    acceptedMediaTypes: [AEP_MEDIA_TYPE],
    ...(options.publicDocumentCache === undefined ? {} : { cache: options.publicDocumentCache }),
    namespace: "platform-discovery",
    parse: parsePlatformDiscoveryDocument,
    sameOriginRedirects: true,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    url: discoveryUrl
  });
  const document = fetched.value;

  return {
    document,
    discoveryUrl: fetched.finalUrl,
    freshness: fetched.freshness,
    endpointUrl: (endpoint) => new URL(requireEndpointPath(document, endpoint), platformUrl)
  };
}

export async function provisionPlatformIdentity(
  options: ProvisionPlatformIdentityOptions
): Promise<ProvisionPlatformIdentityResult> {
  const fetchImpl = requireFetch();
  const discovery =
    options.discovery ??
    (await discoverPlatform({
      ...(options.publicDocumentCache === undefined
        ? {}
        : { publicDocumentCache: options.publicDocumentCache }),
      platformUrl: options.platformUrl
    }));
  const commandUrl = discovery.endpointUrl("provision");
  const body = createPlatformProvisionRequest({
    idempotencyKey: options.idempotencyKey,
    serviceDid: options.serviceDid
  });
  const authenticationHeaders = await resolvePlatformAuthenticationHeaders(options);
  const response = await fetchImpl(commandUrl, {
    body: JSON.stringify(body),
    headers: {
      ...authenticationHeaders,
      Accept: AEP_MEDIA_TYPE,
      "Content-Type": AEP_MEDIA_TYPE,
      "Idempotency-Key": options.idempotencyKey
    },
    method: "POST"
  });

  await throwCommandError(response, "Platform provision");

  return {
    body: parsePlatformAgentIdentity(await response.json()),
    commandUrl,
    status: response.status
  };
}

export async function listPlatformIdentities(
  options: ListPlatformIdentitiesOptions
): Promise<ListPlatformIdentitiesResult> {
  const fetchImpl = requireFetch();
  const discovery =
    options.discovery ??
    (await discoverPlatform({
      platformUrl: options.platformUrl,
      ...(options.publicDocumentCache === undefined
        ? {}
        : { publicDocumentCache: options.publicDocumentCache })
    }));
  const commandUrl = discovery.endpointUrl("list");
  if (options.descending !== undefined)
    commandUrl.searchParams.set("descending", String(options.descending));
  if (options.limit !== undefined) commandUrl.searchParams.set("limit", String(options.limit));
  if (options.offset !== undefined) commandUrl.searchParams.set("offset", String(options.offset));
  if (options.serviceDid !== undefined)
    commandUrl.searchParams.set("service_did", options.serviceDid);
  if (options.status !== undefined) commandUrl.searchParams.set("status", options.status);
  const authenticationHeaders = await resolvePlatformAuthenticationHeaders(options);
  const response = await fetchImpl(commandUrl, {
    headers: { ...authenticationHeaders, Accept: AEP_MEDIA_TYPE }
  });
  await throwCommandError(response, "Platform identity list");
  return {
    body: parsePlatformAgentIdentityList(await response.json()),
    commandUrl,
    status: response.status
  };
}

export function createPlatformDelegatedSigner(
  options: PlatformDelegatedSignerOptions
): AepClientAssertionSigner {
  return async (claims, context) => {
    const fetchImpl = requireFetch();
    const discovery =
      options.discovery ??
      (await discoverPlatform({
        ...(options.publicDocumentCache === undefined
          ? {}
          : { publicDocumentCache: options.publicDocumentCache }),
        platformUrl: options.platformUrl
      }));
    const commandUrl = endpointUrlWithIdentity(
      discovery,
      "sign",
      options.identity.agent_identity_id
    );
    const lifetimeSeconds = claims.exp - claims.iat;
    const request = createPlatformSignRequest({
      command: claims.op,
      jti: claims.jti,
      lifetimeSeconds,
      ...(claims.resource === undefined ? {} : { resource: claims.resource }),
      ...(context.platformContext === undefined
        ? {}
        : { platformContext: context.platformContext }),
      serviceDid: claims.aud
    });
    const idempotencyKey =
      context.idempotencyKey ??
      (typeof options.idempotencyKey === "function"
        ? options.idempotencyKey()
        : options.idempotencyKey) ??
      randomJti();
    const authenticationHeaders = await resolvePlatformAuthenticationHeaders(options);
    const response = await fetchImpl(commandUrl, {
      body: JSON.stringify(request),
      headers: {
        ...authenticationHeaders,
        Accept: AEP_MEDIA_TYPE,
        "Content-Type": AEP_MEDIA_TYPE,
        "Idempotency-Key": idempotencyKey
      },
      method: "POST",
      ...(context.signal === undefined ? {} : { signal: context.signal })
    });

    await throwCommandError(response, "Platform sign");

    const parsed = parsePlatformSignResponse(await response.json());
    if (parsed.status === "pending") {
      return {
        status: "pending",
        ...(parsed.platform_context === undefined
          ? {}
          : { platformContext: parsed.platform_context }),
        retryAfterSeconds: Number(parsed.retry_after_seconds)
      };
    }
    return {
      status: "completed",
      clientAssertion: parsed.client_assertion,
      ...(parsed.platform_context === undefined ? {} : { platformContext: parsed.platform_context })
    };
  };
}

async function resolvePlatformAuthenticationHeaders(options: {
  authenticationHeaders?: PlatformAuthenticationHeadersInput;
  authorization?: string;
}): Promise<PlatformAuthenticationHeaders> {
  const supplied =
    typeof options.authenticationHeaders === "function"
      ? await options.authenticationHeaders()
      : (options.authenticationHeaders ?? {});
  const headers: PlatformAuthenticationHeaders = {
    ...(options.authorization === undefined ? {} : { Authorization: options.authorization })
  };
  for (const [name, value] of Object.entries(supplied)) {
    const normalized = name.toLowerCase();
    if (
      normalized === "accept" ||
      normalized === "content-type" ||
      normalized === "idempotency-key"
    ) {
      continue;
    }
    headers[name] = value;
  }
  return headers;
}

export function createPlatformIdentityProvider(
  options: CreatePlatformIdentityProviderOptions
): PlatformIdentityProvider {
  let discoveryPromise: Promise<DiscoverPlatformResult> | undefined;

  const discovery = (): Promise<DiscoverPlatformResult> => {
    discoveryPromise ??= discoverPlatform({
      platformUrl: options.platformUrl,
      ...(options.publicDocumentCache === undefined
        ? {}
        : { publicDocumentCache: options.publicDocumentCache })
    });
    return discoveryPromise;
  };

  const findIdentityByServiceDid = async (
    serviceDid: string
  ): Promise<AgentServiceIdentity | undefined> => {
    const result = await listPlatformIdentities({
      ...(options.authenticationHeaders === undefined
        ? {}
        : { authenticationHeaders: options.authenticationHeaders }),
      ...(options.authorization === undefined ? {} : { authorization: options.authorization }),
      descending: true,
      discovery: await discovery(),
      limit: 100,
      platformUrl: options.platformUrl,
      serviceDid
    });
    const identity = result.body.data.find((candidate) => candidate.status === "active");
    return identity === undefined
      ? undefined
      : agentServiceIdentityFromPlatform(identity, options.platformUrl);
  };

  return {
    findIdentityByServiceDid,
    async getOrCreateIdentity(input) {
      const existing = await findIdentityByServiceDid(input.serviceDid);
      if (existing !== undefined) return existing;
      const platformDiscovery = await discovery();
      const idempotencyKey =
        typeof options.idempotencyKey === "function"
          ? options.idempotencyKey(input)
          : (options.idempotencyKey ?? randomJti());
      const result = await provisionPlatformIdentity({
        ...(options.authenticationHeaders === undefined
          ? {}
          : { authenticationHeaders: options.authenticationHeaders }),
        ...(options.authorization === undefined ? {} : { authorization: options.authorization }),
        discovery: platformDiscovery,
        idempotencyKey,
        platformUrl: options.platformUrl,
        serviceDid: input.serviceDid
      });

      return agentServiceIdentityFromPlatform(result.body, options.platformUrl);
    },
    async signerFor(identity) {
      if (identity.identityKind !== "platform-hosted") {
        throw new TypeError("Platform identity provider cannot sign for a sovereign identity.");
      }

      const platformDiscovery = await discovery();

      return createPlatformDelegatedSigner({
        ...(options.authenticationHeaders === undefined
          ? {}
          : { authenticationHeaders: options.authenticationHeaders }),
        ...(options.authorization === undefined ? {} : { authorization: options.authorization }),
        discovery: platformDiscovery,
        identity: platformAgentIdentityFromAgentIdentity(identity),
        platformUrl: options.platformUrl
      });
    }
  };
}

function agentServiceIdentityFromPlatform(
  identity: PlatformAgentIdentity,
  platformUrl: string | URL
): AgentServiceIdentity {
  return {
    agentDid: identity.agent_did,
    identityKind: "platform-hosted",
    metadata: {
      agentIdentityId: identity.agent_identity_id,
      createdAt: identity.created_at,
      didDocumentUrl: identity.did_document_url,
      keyId: identity.key_id,
      platformUrl: String(platformUrl),
      status: identity.status,
      updatedAt: identity.updated_at
    },
    serviceDid: identity.service_did,
    signingAlgorithms: [...identity.signing_algorithms]
  };
}

function platformAgentIdentityFromAgentIdentity(
  identity: AgentServiceIdentity
): PlatformAgentIdentity {
  const metadata = identity.metadata ?? {};

  return {
    agent_did: identity.agentDid,
    agent_identity_id: metadataString(metadata, "agentIdentityId"),
    created_at: metadataString(metadata, "createdAt"),
    did_document_url: metadataString(metadata, "didDocumentUrl"),
    key_id: metadataString(metadata, "keyId"),
    service_did: identity.serviceDid,
    signing_algorithms: [...identity.signingAlgorithms],
    status: parseManagedAgentStatus(metadataString(metadata, "status")),
    updated_at: metadataString(metadata, "updatedAt")
  };
}

export function selectGrantType(
  inspect: InspectDocument | InspectServiceResult,
  options: SelectGrantTypeOptions = {}
): AepGrantType {
  const document = isInspectServiceResult(inspect) ? inspect.document : inspect;
  const advertised = document.commands.grant_types ?? [];
  const preferred = options.preferredGrantTypes ?? advertised;

  for (const grantType of preferred) {
    if (advertised.includes(grantType)) {
      return grantType;
    }
  }

  throw new TypeError("AEP Service does not advertise a compatible grant type.");
}

export function createInMemorySessionCredentialStore(
  records: AepSessionCredentialRecord[] = []
): AepSessionCredentialStore {
  const credentials = new Map<string, AepSessionCredentialRecord>();

  records.forEach((record) =>
    credentials.set(sessionCredentialKey(record), cloneCredential(record))
  );

  return {
    deleteCredential(serviceDid, credentialId) {
      purgeInvalidCredentials(credentials, new Date());
      for (const [key, record] of credentials) {
        if (record.serviceDid === serviceDid && record.credentialId === credentialId) {
          credentials.delete(key);
        }
      }
    },
    findCredential(serviceDid, credentialId) {
      purgeInvalidCredentials(credentials, new Date());
      for (const record of credentials.values()) {
        if (record.serviceDid === serviceDid && record.credentialId === credentialId) {
          return cloneCredential(record);
        }
      }

      return undefined;
    },
    findUsableCredential(serviceDid, now = new Date()) {
      purgeInvalidCredentials(credentials, now);
      const nowMs = now.getTime();

      for (const record of credentials.values()) {
        if (record.serviceDid !== serviceDid) {
          continue;
        }

        if (record.expiresAt !== undefined) {
          const expiry = Date.parse(record.expiresAt);
          if (Number.isNaN(expiry) || expiry <= nowMs) continue;
        }

        return cloneCredential(record);
      }

      return undefined;
    },
    listCredentials(serviceDid) {
      purgeInvalidCredentials(credentials, new Date());
      return [...credentials.values()]
        .filter((record) => record.serviceDid === serviceDid)
        .map(cloneCredential);
    },
    saveCredential(record) {
      purgeInvalidCredentials(credentials, new Date());
      parseBuiltInGrantResponse(record.grantType, record.credential);
      const cloned = cloneCredential(record);
      credentials.set(sessionCredentialKey(cloned), cloned);
      return cloneCredential(cloned);
    }
  };
}

function purgeInvalidCredentials(
  credentials: Map<string, AepSessionCredentialRecord>,
  now: Date
): void {
  for (const [key, record] of credentials) {
    try {
      parseBuiltInGrantResponse(record.grantType, record.credential);
      if (record.expiresAt === undefined || Date.parse(record.expiresAt) <= now.getTime()) {
        credentials.delete(key);
      }
    } catch {
      credentials.delete(key);
    }
  }
}

async function findCompatibleCredential(
  store: AgentCredentialStore,
  serviceDid: string,
  grantType?: AepGrantType,
  methods?: AepAuthenticationMethod[]
): Promise<AgentCredentialRecord | undefined> {
  const records = await store.listCredentials(serviceDid);
  return records.find(
    (record) =>
      (grantType === undefined || record.grantType === grantType) &&
      (methods === undefined || methods.includes(record.grantType))
  );
}

export function createInMemoryAgentIdentityStore(
  records: AgentServiceIdentity[] = []
): AgentIdentityStore {
  const identities = new Map<string, AgentServiceIdentity>();

  records.forEach((record) => identities.set(record.serviceDid, cloneAgentIdentity(record)));

  return {
    findByServiceDid(serviceDid) {
      const identity = identities.get(serviceDid);

      return identity === undefined ? undefined : cloneAgentIdentity(identity);
    },
    saveIdentity(identity) {
      const cloned = cloneAgentIdentity(identity);
      identities.set(cloned.serviceDid, cloned);
      return cloneAgentIdentity(cloned);
    }
  };
}

export function createRandomIdempotencyKeyProvider(
  generator: () => string = randomJti
): AgentIdempotencyKeyProvider {
  return {
    createKey: () => generator()
  };
}

export function createInMemoryInspectCache(
  records: Array<{ result: CachedInspectServiceResult; serviceUrl: string }> = []
): AgentInspectCache {
  const cache = new Map<string, CachedInspectServiceResult>();

  records.forEach((record) => cache.set(record.serviceUrl, cloneCachedInspect(record.result)));

  return {
    delete(serviceUrl) {
      cache.delete(serviceUrl);
    },
    get(serviceUrl) {
      const cached = cache.get(serviceUrl);

      return cached === undefined ? undefined : cloneCachedInspect(cached);
    },
    set(serviceUrl, result) {
      cache.set(serviceUrl, cloneCachedInspect(result));
    }
  };
}

function inspectCacheFresh(result: CachedInspectServiceResult, now: Date): boolean {
  const cachedAt = Date.parse(result.cachedAt);
  if (Number.isNaN(cachedAt)) return false;
  const directives = cacheControlDirectives(result.cacheControl);
  if (directives.has("no-cache") || directives.has("no-store")) return false;
  const maxAge = directives.get("max-age");
  const seconds = maxAge === undefined ? 300 : Number(maxAge);
  return Number.isSafeInteger(seconds) && seconds >= 0 && cachedAt + seconds * 1000 > now.getTime();
}

function inspectCacheNoStore(cacheControl: string | undefined): boolean {
  return cacheControlDirectives(cacheControl).has("no-store");
}

function cacheControlDirectives(value: string | undefined): Map<string, string | undefined> {
  const directives = new Map<string, string | undefined>();
  for (const part of value?.split(",") ?? []) {
    const [rawName, rawValue] = part.trim().split("=", 2);
    if (rawName === undefined || rawName.length === 0) continue;
    directives.set(rawName.toLowerCase(), rawValue?.trim().replace(/^"|"$/g, ""));
  }
  return directives;
}

export function sessionCredentialRecordFromGrantResult(
  result: GrantServiceResult,
  options: {
    clock?: () => Date;
    grantType: AepGrantType;
    inspect: InspectDocument | InspectServiceResult;
    serviceUrl?: string | URL;
  }
): AepSessionCredentialRecord {
  const credentialId = credentialIdFromGrantResult(result.body);
  const document = isInspectServiceResult(options.inspect)
    ? options.inspect.document
    : options.inspect;
  const expiresAt = expiresAtFromGrantResult(result.body);

  return {
    credential: structuredClone(result.body),
    credentialId,
    grantType: options.grantType,
    issuedAt: (options.clock ?? (() => new Date()))().toISOString(),
    serviceDid: document.service.did,
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(options.serviceUrl === undefined ? {} : { serviceUrl: String(options.serviceUrl) })
  };
}

export function credentialPresentationHeaders(
  credential: AepBuiltInGrantResponse,
  carrier: AepProtectedResourceAuthorizationCarrier = "standard"
): Record<string, string> {
  if (isOAuthBearerGrantResponse(credential)) {
    return renderProtectedResourceAuthorization({
      carrier,
      scheme: "Bearer",
      credentials: credential.access_token
    });
  }

  if (isApiKeyGrantResponse(credential)) {
    return {
      [credential.header]: credential.api_key
    };
  }

  if (isBasicGrantResponse(credential)) {
    return renderProtectedResourceAuthorization({
      carrier,
      scheme: "Basic",
      credentials: base64(`${credential.username}:${credential.password}`)
    });
  }

  throw new TypeError("Unsupported AEP built-in credential.");
}

export async function clientAssertionAuthenticationHeaders(
  options: ClientAssertionAuthenticationHeadersOptions
): Promise<Record<string, string>> {
  const document = options.inspect === undefined ? undefined : inspectDocument(options.inspect);
  const serviceDid = options.serviceDid ?? document?.service.did;

  if (serviceDid === undefined) {
    throw new TypeError("AEP client assertion authentication headers require a service DID.");
  }

  const signingAlgorithms = options.signingAlgorithms ?? document?.core.signing_algorithms;
  const clientAssertion = await signClientAssertion({
    agentDid: options.agentDid,
    command: options.command ?? (options.resource === undefined ? "status" : "authenticate"),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.jti === undefined ? {} : { jti: options.jti }),
    serviceDid,
    ...(options.pendingSignResolver === undefined
      ? {}
      : { pendingSignResolver: options.pendingSignResolver }),
    ...(options.platformContext === undefined ? {} : { platformContext: options.platformContext }),
    ...(options.resource === undefined ? {} : { resource: String(options.resource) }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    signer: options.signer,
    ...(signingAlgorithms === undefined ? {} : { signingAlgorithms }),
    ...(options.ttlSeconds === undefined ? {} : { ttlSeconds: options.ttlSeconds })
  });

  return renderProtectedResourceAuthorization({
    ...(options.carrier === undefined ? {} : { carrier: options.carrier }),
    scheme: AEP_AUTH_SCHEME,
    credentials: clientAssertion
  });
}

export async function protectedResourceAuthenticationHeaders(
  options: ProtectedResourceAuthenticationHeadersOptions
): Promise<Record<string, string>> {
  if ("credential" in options) {
    return credentialPresentationHeaders(options.credential, options.carrier);
  }

  return clientAssertionAuthenticationHeaders(options);
}

export async function probeProtectedResource(
  options: ProbeProtectedResourceOptions
): Promise<ProbeProtectedResourceResult> {
  const response = await globalFetch()(options.url, {
    ...(options.body === undefined ? {} : { body: options.body }),
    ...(options.headers === undefined ? {} : { headers: options.headers }),
    method: options.method ?? "GET",
    redirect: "manual",
    ...(options.signal === undefined ? {} : { signal: options.signal })
  });
  const challenge = parseAepAuthenticationChallenge(response.headers.get("www-authenticate"));
  return {
    ...(challenge === undefined ? {} : { challenge }),
    classification: response.ok
      ? "success"
      : response.status === 401 && challenge !== undefined
        ? "aep-challenge"
        : response.status === 401
          ? "unrelated-authentication"
          : "http-response",
    response
  };
}

export async function fetchProtectedResource(
  options: FetchProtectedResourceOptions
): Promise<Response> {
  assertReplayableBody(options.body);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 30_000);
  const signal =
    options.signal === undefined
      ? controller.signal
      : AbortSignal.any([options.signal, controller.signal]);
  try {
    let target = new URL(options.url);
    const initialOrigin = target.origin;
    let redirects = 0;
    for (;;) {
      const session = options.agent.serviceSession({ serviceUrl: target.origin });
      let policy: AepOpenApiOperationPolicy | undefined;
      try {
        policy = await session.openApiPolicy({
          ...(options.method === undefined ? {} : { method: options.method }),
          signal,
          url: target
        });
      } catch {
        policy = undefined;
      }
      const anonymous =
        policy?.state === "required"
          ? undefined
          : await probeProtectedResource({
              ...(options.body === undefined ? {} : { body: options.body }),
              ...(options.headers === undefined
                ? {}
                : { headers: withoutAuthenticationHeaders(options.headers) }),
              ...(options.method === undefined ? {} : { method: options.method }),
              signal,
              url: target
            });
      if (anonymous !== undefined && isRedirect(anonymous.response.status)) {
        target = redirectTarget(anonymous.response, target, redirects++, options.maxRedirects ?? 5);
        continue;
      }
      if (
        anonymous !== undefined &&
        (anonymous.classification !== "aep-challenge" || anonymous.challenge === undefined)
      ) {
        return anonymous.response;
      }
      if (
        anonymous !== undefined &&
        anonymous.challenge !== undefined &&
        anonymous.challenge.inspect.origin !== target.origin
      ) {
        throw new AepInspectError("AEP challenge Inspect URI changed origin.", "invalid_redirect");
      }
      const inspected = await session.inspect();
      if (
        anonymous !== undefined &&
        anonymous.challenge !== undefined &&
        inspected.document.service.did !== anonymous.challenge.serviceDid
      ) {
        throw new AepInspectError(
          "AEP challenge Service DID did not match Inspect.",
          "validation_failed"
        );
      }
      const methods =
        policy?.state === "required"
          ? policy.methods
          : (inspected.document.authentication?.methods ?? []);
      if (methods.length === 0) {
        if (anonymous !== undefined) return anonymous.response;
        throw new TypeError("OpenAPI requires authentication but supplies no usable AEP method.");
      }
      const selectedGrant = options.grantType ?? methods.find((method) => method !== "aep-jwt");
      let headers: Record<string, string>;
      try {
        headers = await session.authenticationHeaders({
          ...(options.carrier === undefined ? {} : { carrier: options.carrier }),
          ...(options.credentialId === undefined ? {} : { credentialId: options.credentialId }),
          ...(options.grantType === undefined ? {} : { grantType: options.grantType }),
          resource: String(target),
          signal
        });
      } catch (error) {
        if (
          error instanceof AepPendingSignError ||
          error instanceof AepPendingSignResolverError ||
          signal.aborted
        )
          throw error;
        if (selectedGrant === undefined) throw error;
        await session.grant({ grantType: selectedGrant, signal });
        headers = await session.authenticationHeaders({
          ...(options.carrier === undefined ? {} : { carrier: options.carrier }),
          grantType: selectedGrant,
          resource: String(target),
          signal
        });
      }
      const authenticated = await globalFetch()(target, {
        ...(options.body === undefined ? {} : { body: options.body }),
        headers: mergeAuthoritativeHeaders(
          target.origin === initialOrigin
            ? options.headers
            : withoutAuthenticationHeaders(options.headers),
          target.origin === initialOrigin ? options.additionalAuthenticationHeaders : undefined,
          headers
        ),
        method: options.method ?? "GET",
        redirect: "manual",
        signal
      });
      if (isRedirect(authenticated.status)) {
        const next = redirectTarget(authenticated, target, redirects++, options.maxRedirects ?? 5);
        target = next;
        continue;
      }
      return authenticated;
    }
  } finally {
    clearTimeout(timeout);
  }
}

function parseAepAuthenticationChallenge(
  value: string | null
): AepAuthenticationChallenge | undefined {
  if (value === null || !/^AEP(?:\s|$)/i.test(value)) return undefined;
  const parameters: Record<string, string> = {};
  for (const match of value.matchAll(/([a-z_]+)="([^"]*)"/gi)) {
    const name = match[1];
    const parameterValue = match[2];
    if (name !== undefined && parameterValue !== undefined) {
      parameters[name.toLowerCase()] = parameterValue;
    }
  }
  if (parameters["service_did"] === undefined || parameters["inspect"] === undefined)
    return undefined;
  try {
    const inspect = new URL(parameters["inspect"]);
    if (
      inspect.protocol !== "https:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(inspect.hostname)
    )
      return undefined;
    return {
      inspect,
      ...(parameters["reason"] === undefined ? {} : { reason: parameters["reason"] }),
      serviceDid: parameters["service_did"]
    };
  } catch {
    return undefined;
  }
}

function mergeAuthoritativeHeaders(
  caller: RequestInit["headers"],
  additional: Readonly<Record<string, string>> | undefined,
  controlled: Record<string, string>
): Headers {
  const headers = new Headers(caller);
  const controlledNames = new Set(Object.keys(controlled).map((name) => name.toLowerCase()));
  for (const [name, value] of Object.entries(additional ?? {})) {
    if (
      controlledNames.has(name.toLowerCase()) ||
      name.toLowerCase() === AEP_AUTHORIZATION_HEADER.toLowerCase()
    ) {
      throw new AepAuthorizationCarrierError(
        "An additional authentication field conflicts with the selected AEP presentation.",
        "invalid_request"
      );
    }
    headers.set(name, value);
  }
  headers.delete(AEP_AUTHORIZATION_HEADER);
  if (controlledNames.has("authorization")) headers.delete("authorization");
  for (const [name, value] of Object.entries(controlled)) headers.set(name, value);
  return headers;
}

function withoutAuthenticationHeaders(headers: RequestInit["headers"]): Headers {
  const sanitized = new Headers(headers);
  sanitized.delete("authorization");
  sanitized.delete(AEP_AUTHORIZATION_HEADER);
  return sanitized;
}

function assertReplayableBody(body: RequestInit["body"]): void {
  if (
    body !== undefined &&
    body !== null &&
    typeof ReadableStream !== "undefined" &&
    body instanceof ReadableStream
  ) {
    throw new TypeError("AEP authentication requires a replayable request body.");
  }
}

function isRedirect(status: number): boolean {
  return [301, 302, 303, 307, 308].includes(status);
}

function redirectTarget(response: Response, current: URL, redirects: number, maximum: number): URL {
  if (redirects >= maximum)
    throw new AepInspectError("Protected-resource redirect limit exceeded.", "invalid_redirect");
  const location = response.headers.get("location");
  if (location === null)
    throw new AepInspectError("Redirect omitted Location.", "invalid_redirect");
  return new URL(location, current);
}

function globalFetch(): typeof fetch {
  if (typeof globalThis.fetch !== "function")
    throw new TypeError("AEP resource fetch requires global fetch.");
  return globalThis.fetch;
}

export async function inspectService(
  options: InspectServiceOptions
): Promise<InspectServiceResult> {
  const serviceUrl = resolveServiceReference(options.serviceUrl);
  if (options.publicDocumentCache !== undefined) {
    const inspectUrl = new URL(AEP_WELL_KNOWN_PATH, serviceUrl);
    try {
      const fetched = await fetchAepPublicDocument({
        accept: AEP_MEDIA_TYPE,
        acceptedMediaTypes: [AEP_MEDIA_TYPE],
        cache: options.publicDocumentCache,
        ...(options.clock === undefined ? {} : { clock: options.clock }),
        ...(options.maxResponseBytes === undefined
          ? {}
          : { maxResponseBytes: options.maxResponseBytes }),
        namespace: "inspect",
        parse: parseInspectDocument,
        sameOriginRedirects: true,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        url: inspectUrl
      });
      const document = fetched.value;
      return {
        document,
        inspectUrl,
        finalUrl: fetched.finalUrl,
        commandUrl: (command) => new URL(commandPathFromInspect(document, command), serviceUrl),
        ...(fetched.cacheControl === undefined ? {} : { cacheControl: fetched.cacheControl }),
        ...(fetched.etag === undefined ? {} : { etag: fetched.etag }),
        ...(fetched.lastModified === undefined ? {} : { lastModified: fetched.lastModified })
      };
    } catch (error) {
      throw new AepInspectError(
        error instanceof Error ? error.message : "AEP Inspect failed.",
        "http_error"
      );
    }
  }
  const cacheKey = String(serviceUrl);
  const now = (options.clock ?? (() => new Date()))();
  const cached = await options.inspectCache?.get(cacheKey);
  if (cached !== undefined && inspectCacheFresh(cached, now)) return cached;
  const fetched = await fetchInspectService({ ...options, serviceUrl }, cached);
  if ("notModified" in fetched) {
    if (cached === undefined)
      throw new AepInspectError(
        "AEP Inspect returned 304 without a cached document.",
        "http_error",
        304
      );
    const refreshed: CachedInspectServiceResult = {
      ...cached,
      cachedAt: now.toISOString(),
      ...(fetched.cacheControl === undefined ? {} : { cacheControl: fetched.cacheControl }),
      ...(fetched.etag === undefined ? {} : { etag: fetched.etag }),
      ...(fetched.lastModified === undefined ? {} : { lastModified: fetched.lastModified })
    };
    if (inspectCacheNoStore(refreshed.cacheControl)) await options.inspectCache?.delete(cacheKey);
    else await options.inspectCache?.set(cacheKey, refreshed);
    return refreshed;
  }
  const inspected = fetched;
  if (options.inspectCache !== undefined && !inspectCacheNoStore(inspected.cacheControl)) {
    await options.inspectCache.set(cacheKey, { ...inspected, cachedAt: now.toISOString() });
  } else if (options.inspectCache !== undefined) await options.inspectCache.delete(cacheKey);
  return inspected;
}

interface InspectNotModifiedResult {
  notModified: true;
  cacheControl?: string;
  etag?: string;
  lastModified?: string;
}

async function fetchInspectService(
  options: InspectServiceOptions,
  cached?: CachedInspectServiceResult
): Promise<InspectServiceResult | InspectNotModifiedResult> {
  const fetchImpl = requireFetch();

  const serviceUrl = resolveServiceReference(options.serviceUrl);
  const inspectUrl = new URL(AEP_WELL_KNOWN_PATH, serviceUrl);
  const maxBytes = options.maxResponseBytes ?? 1024 * 1024;
  let current = inspectUrl;
  let response: ResponseLike;
  try {
    for (let redirects = 0; ; redirects += 1) {
      response = await fetchImpl(current, {
        headers: {
          Accept: AEP_MEDIA_TYPE,
          ...(cached?.etag === undefined ? {} : { "If-None-Match": cached.etag }),
          ...(cached?.lastModified === undefined
            ? {}
            : { "If-Modified-Since": cached.lastModified })
        },
        redirect: "manual",
        ...(options.signal === undefined ? {} : { signal: options.signal })
      });
      if (![301, 302, 303, 307, 308].includes(response.status)) break;
      if (redirects >= 5)
        throw new AepInspectError("AEP Inspect exceeded five redirects.", "invalid_redirect");
      const location = response.headers.get("location");
      if (location === null)
        throw new AepInspectError("AEP Inspect redirect omitted Location.", "invalid_redirect");
      const next = new URL(location, current);
      if (next.origin !== current.origin || next.protocol !== current.protocol)
        throw new AepInspectError(
          "AEP Inspect redirect changed origin or scheme.",
          "invalid_redirect"
        );
      current = next;
    }
  } catch (error) {
    if (error instanceof AepInspectError) throw error;
    throw new AepInspectError("AEP Inspect was aborted or could not be fetched.", "aborted");
  }

  if (response.status === 304) {
    const cacheControl = response.headers.get("cache-control") ?? undefined;
    const etag = response.headers.get("etag") ?? undefined;
    const lastModified = response.headers.get("last-modified") ?? undefined;
    return {
      notModified: true,
      ...(cacheControl === undefined ? {} : { cacheControl }),
      ...(etag === undefined ? {} : { etag }),
      ...(lastModified === undefined ? {} : { lastModified })
    };
  }

  if (!response.ok) {
    throw new AepInspectError(
      `AEP Inspect failed with HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}.`,
      "http_error",
      response.status
    );
  }

  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== AEP_MEDIA_TYPE)
    throw new AepInspectError("AEP Inspect response media type is invalid.", "invalid_media_type");
  let raw: string;
  try {
    raw = await readBoundedResponse(response, maxBytes);
  } catch (error) {
    if (error instanceof AepInspectError) throw error;
    throw new AepInspectError("AEP Inspect response could not be read.", "invalid_json");
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new AepInspectError("AEP Inspect response contains malformed JSON.", "invalid_json");
  }
  let document: InspectDocument;
  try {
    document = parseInspectDocument(value);
  } catch {
    throw new AepInspectError("AEP Inspect document failed validation.", "validation_failed");
  }

  const cacheControl = response.headers.get("cache-control") ?? undefined;
  const etag = response.headers.get("etag") ?? undefined;
  const lastModified = response.headers.get("last-modified") ?? undefined;

  return {
    document,
    inspectUrl,
    finalUrl: current,
    commandUrl: (command) => new URL(commandPathFromInspect(document, command), serviceUrl),
    ...(cacheControl === undefined ? {} : { cacheControl }),
    ...(etag === undefined ? {} : { etag }),
    ...(lastModified === undefined ? {} : { lastModified })
  };
}

async function readBoundedResponse(response: ResponseLike, maxBytes: number): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1)
    throw new RangeError("maxResponseBytes must be positive.");
  if (response.body !== undefined && response.body !== null) {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new AepInspectError("AEP Inspect response is too large.", "response_too_large");
      }
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return new TextDecoder().decode(bytes);
  }
  const text =
    response.text === undefined ? JSON.stringify(await response.json()) : await response.text();
  if (new TextEncoder().encode(text).byteLength > maxBytes)
    throw new AepInspectError("AEP Inspect response is too large.", "response_too_large");
  return text;
}

export async function enrollService(options: EnrollServiceOptions): Promise<EnrollServiceResult> {
  const fetchImpl = requireFetch();
  const inspect = await resolveInspect(options);
  const commandUrl = commandUrlFromInspect(options.serviceUrl, inspect, "enroll");
  const claimValues =
    options.claims === undefined ? undefined : parseAepClaimValues(options.claims);
  const missingRequiredClaimNames = missingAepRequiredClaimNames(
    inspect.document.claims?.required ?? [],
    claimValues
  );
  if (missingRequiredClaimNames.length > 0) {
    throw new AepClaimRequirementsError(missingRequiredClaimNames);
  }

  const clientAssertion = await resolveClientAssertion(options, inspect, "enroll");
  const body = {
    agent_did: options.agentDid,
    ...(claimValues === undefined ? {} : { claims: structuredClone(claimValues) }),
    idempotency_key: options.idempotencyKey
  };
  const response = await fetchImpl(commandUrl, {
    body: JSON.stringify(body),
    headers: {
      Accept: AEP_MEDIA_TYPE,
      Authorization: `${AEP_AUTH_SCHEME} ${clientAssertion}`,
      "Content-Type": AEP_MEDIA_TYPE,
      "Idempotency-Key": options.idempotencyKey
    },
    method: "POST"
  });

  await throwCommandError(response, "Enroll");

  return {
    body: parseEnrollResponse(await response.json()),
    commandUrl,
    status: response.status
  };
}

export async function grantService(options: GrantServiceOptions): Promise<GrantServiceResult> {
  const fetchImpl = requireFetch();
  const inspect = await resolveInspect(options);
  const commandUrl = commandUrlFromInspect(options.serviceUrl, inspect, "grant");
  const clientAssertion = await resolveClientAssertion(options, inspect, "grant");
  const body = parseGrantRequest({
    ...(options.parameters ?? {}),
    grant_type: options.grantType,
    ...(options.requestedScopes === undefined
      ? {}
      : { requested_scopes: [...options.requestedScopes] })
  });
  const response = await fetchImpl(commandUrl, {
    body: JSON.stringify(body),
    headers: {
      Accept: AEP_MEDIA_TYPE,
      Authorization: `${AEP_AUTH_SCHEME} ${clientAssertion}`,
      "Content-Type": AEP_MEDIA_TYPE,
      "Idempotency-Key": options.idempotencyKey
    },
    method: "POST",
    ...(options.signal === undefined ? {} : { signal: options.signal })
  });

  await throwCommandError(response, "Grant");

  return {
    body: parseGrantResponse(body.grant_type, await response.json()),
    commandUrl,
    status: response.status
  };
}

export async function revokeService(options: RevokeServiceOptions): Promise<RevokeServiceResult> {
  const fetchImpl = requireFetch();
  const inspect = await resolveInspect(options);
  const commandUrl = commandUrlFromInspect(options.serviceUrl, inspect, "revoke");
  const clientAssertion = await resolveClientAssertion(options, inspect, "revoke");
  const body = parseRevokeRequest({
    ...(options.parameters ?? {}),
    ...revokeSelectorBody(options)
  });
  const response = await fetchImpl(commandUrl, {
    body: JSON.stringify(body),
    headers: {
      Accept: AEP_MEDIA_TYPE,
      Authorization: `${AEP_AUTH_SCHEME} ${clientAssertion}`,
      "Content-Type": AEP_MEDIA_TYPE,
      "Idempotency-Key": options.idempotencyKey
    },
    method: "POST"
  });

  await throwCommandError(response, "Revoke");

  return {
    body: parseRevokeResponse(await response.json()),
    commandUrl,
    status: response.status
  };
}

export async function statusService(options: StatusServiceOptions): Promise<StatusServiceResult> {
  const fetchImpl = requireFetch();
  const inspect = await resolveInspect(options);
  const commandUrl = commandUrlFromInspect(options.serviceUrl, inspect, "status");
  const clientAssertion = await resolveClientAssertion(options, inspect, "status");
  const response = await fetchImpl(commandUrl, {
    headers: {
      Accept: AEP_MEDIA_TYPE,
      Authorization: `${AEP_AUTH_SCHEME} ${clientAssertion}`
    },
    method: "GET"
  });

  await throwCommandError(response, "Status");

  return {
    body: parseStatusResponse(await response.json()),
    commandUrl,
    status: response.status
  };
}

function normalizePlatformUrl(platformUrl: string | URL): URL {
  const url = platformUrl instanceof URL ? new URL(platformUrl) : new URL(platformUrl);

  if (url.pathname !== "/" || url.search || url.hash) {
    url.pathname = "/";
    url.search = "";
    url.hash = "";
  }

  return url;
}

function normalizeServiceUrl(serviceUrl: string | URL): URL {
  return resolveServiceReference(serviceUrl);
}

function parsePlatformDiscoveryDocument(value: unknown): PlatformDiscoveryDocument {
  const document = requireRecord(value, "Platform discovery document");
  const endpoints = requireRecord(document["endpoints"], "Platform discovery endpoints");
  const http = requireRecord(document["http"], "Platform discovery HTTP metadata");
  const identity = requireRecord(document["identity"], "Platform discovery identity metadata");
  const platform = requireRecord(document["platform"], "Platform discovery platform metadata");
  const signing = requireRecord(document["signing"], "Platform discovery signing metadata");
  const algorithms = requireStringArray(signing, "algorithms");
  const didMethods = requireStringArray(identity, "did_methods");

  return {
    ...document,
    aep_version: requireString(document, "aep_version"),
    endpoints: {
      ...endpoints,
      ...(endpoints["hosted_verification"] === undefined
        ? {}
        : { hosted_verification: requireString(endpoints, "hosted_verification") }),
      lifecycle: requireString(endpoints, "lifecycle"),
      list: requireString(endpoints, "list"),
      provision: requireString(endpoints, "provision"),
      sign: requireString(endpoints, "sign")
    },
    http: {
      ...http,
      endpoint_base: requireString(http, "endpoint_base")
    },
    identity: {
      ...identity,
      did_methods: didMethods,
      did_url_template: requireString(identity, "did_url_template")
    },
    platform: {
      ...platform,
      ...(platform["did"] === undefined ? {} : { did: requireString(platform, "did") }),
      hosted_verification: requireBoolean(platform, "hosted_verification"),
      name: requireString(platform, "name")
    },
    signing: {
      ...signing,
      algorithms,
      default_lifetime_seconds: requireString(signing, "default_lifetime_seconds")
    }
  };
}

function parsePlatformAgentIdentity(value: unknown): PlatformAgentIdentity {
  const body = requireRecord(value, "Platform Agent identity");

  return {
    agent_did: requireString(body, "agent_did"),
    agent_identity_id: requireString(body, "agent_identity_id"),
    created_at: requireString(body, "created_at"),
    did_document_url: requireString(body, "did_document_url"),
    key_id: requireString(body, "key_id"),
    service_did: requireString(body, "service_did"),
    signing_algorithms: requireStringArray(body, "signing_algorithms"),
    status: parseManagedAgentStatus(requireString(body, "status")),
    updated_at: requireString(body, "updated_at")
  };
}

function parsePlatformAgentIdentityList(value: unknown): PlatformAgentIdentityListResponse {
  const body = requireRecord(value, "Platform Agent identity list");
  const data = body["data"];
  if (!Array.isArray(data))
    throw new TypeError("Platform Agent identity list data must be an array.");
  return {
    count: parsePlatformPageCount(body["count"], "count"),
    data: data.map(parsePlatformAgentIdentity),
    total: parsePlatformPageCount(body["total"], "total")
  };
}

function parsePlatformPageCount(value: unknown, field: string): string {
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/.test(value)) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  throw new TypeError(`${field} must be a non-negative integer.`);
}

function parsePlatformSignResponse(value: unknown): PlatformSignResponse {
  const body = requireRecord(value, "Platform sign response");
  const status = requireString(body, "status");
  const platformContext =
    body["platform_context"] === undefined
      ? undefined
      : requireRecord(body["platform_context"], "platform_context");

  if (status === "pending") {
    const retry = requireString(body, "retry_after_seconds");
    const retryNumber = Number(retry);
    if (
      !/^(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$/.test(retry) ||
      retryNumber < 1 ||
      retryNumber > 300
    ) {
      throw new TypeError("retry_after_seconds must be from 1 through 300.");
    }
    return {
      status,
      ...(platformContext === undefined ? {} : { platform_context: platformContext }),
      retry_after_seconds: retry
    };
  }
  if (status !== "completed") {
    throw new TypeError("Platform sign response status must be completed or pending.");
  }

  return {
    status,
    agent_did: requireString(body, "agent_did"),
    client_assertion: requireString(body, "client_assertion"),
    expires_at: requireString(body, "expires_at"),
    issued_at: requireString(body, "issued_at"),
    jti: requireString(body, "jti"),
    ...(platformContext === undefined ? {} : { platform_context: platformContext }),
    service_did: requireString(body, "service_did")
  };
}

function endpointUrlWithIdentity(
  discovery: DiscoverPlatformResult,
  endpoint: keyof PlatformDiscoveryDocument["endpoints"],
  agentIdentityId: string
): URL {
  const endpointUrl = discovery.endpointUrl(endpoint);
  const encodedAgentIdentityTemplate = "%7Bagent_identity_id%7D";

  endpointUrl.pathname = endpointUrl.pathname
    .replace("{agent_identity_id}", encodeURIComponent(agentIdentityId))
    .replace(encodedAgentIdentityTemplate, encodeURIComponent(agentIdentityId));

  return endpointUrl;
}

function requireEndpointPath(
  document: PlatformDiscoveryDocument,
  endpoint: keyof PlatformDiscoveryDocument["endpoints"]
): string {
  const value = document.endpoints[endpoint];

  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`Platform discovery does not advertise ${String(endpoint)}.`);
  }

  return value;
}

function inspectDocument(inspect: InspectDocument | InspectServiceResult): InspectDocument {
  return isInspectServiceResult(inspect) ? inspect.document : inspect;
}

function requireFetch(): FetchLike {
  const resolved: unknown = globalThis.fetch;

  if (typeof resolved !== "function") {
    throw new TypeError("AEP agent requires a fetch implementation.");
  }

  return resolved as FetchLike;
}

async function resolveInspect(options: AepCommandOptions): Promise<InspectServiceResult> {
  return (
    options.inspect ??
    (await inspectService({
      serviceUrl: options.serviceUrl,
      ...(options.signal === undefined ? {} : { signal: options.signal })
    }))
  );
}

function commandUrlFromInspect(
  serviceUrl: string | URL,
  inspect: InspectServiceResult,
  command: AepHttpCommand
): URL {
  if (!inspect.document.commands.supported.includes(command)) {
    throw new TypeError(`AEP Service does not advertise ${command}.`);
  }

  return new URL(
    commandPathFromInspect(inspect.document, command),
    normalizeServiceUrl(serviceUrl)
  );
}

async function resolveClientAssertion(
  options: AepCommandOptions,
  inspect: InspectServiceResult,
  command: AepAuthenticatedCommand
): Promise<string> {
  if (options.clientAssertion !== undefined) {
    return options.clientAssertion;
  }

  if (options.clientAssertionSigner === undefined) {
    throw new TypeError("AEP command requires clientAssertion or clientAssertionSigner.");
  }

  if (options.agentDid === undefined) {
    throw new TypeError("AEP command signing requires agentDid.");
  }

  return signClientAssertion({
    agentDid: options.agentDid,
    command,
    serviceDid: inspect.document.service.did,
    signer: options.clientAssertionSigner,
    ...(options.platformContext === undefined ? {} : { platformContext: options.platformContext }),
    ...(options.pendingSignResolver === undefined
      ? {}
      : { pendingSignResolver: options.pendingSignResolver }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(options.assertionClock === undefined ? {} : { clock: options.assertionClock }),
    ...(options.assertionJti === undefined ? {} : { jti: options.assertionJti }),
    ...(inspect.document.core.signing_algorithms === undefined
      ? {}
      : { signingAlgorithms: inspect.document.core.signing_algorithms }),
    ...(options.assertionTtlSeconds === undefined
      ? {}
      : { ttlSeconds: options.assertionTtlSeconds })
  });
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new DOMException("Aborted", "AbortError");
  }
}

function assertionOptionsWithDefinedValues(
  options: Pick<AepAgentOptions, "assertionClock" | "assertionJti" | "assertionTtlSeconds">
): Pick<AepAgentOptions, "assertionClock" | "assertionJti" | "assertionTtlSeconds"> {
  return {
    ...(options.assertionClock === undefined ? {} : { assertionClock: options.assertionClock }),
    ...(options.assertionJti === undefined ? {} : { assertionJti: options.assertionJti }),
    ...(options.assertionTtlSeconds === undefined
      ? {}
      : { assertionTtlSeconds: options.assertionTtlSeconds })
  };
}

function revokeSelectorBody(options: RevokeServiceOptions): RevokeRequest {
  if (options.allGrantTypes === true) {
    return {
      all_grant_types: "true"
    };
  }

  if (options.credentialId !== undefined) {
    return {
      credential_id: options.credentialId
    };
  }

  return {
    grant_type: options.grantType
  };
}

function parseGrantResponse(
  grantType: AepGrantType,
  value: unknown
): AepBuiltInGrantResponse | Record<string, unknown> {
  if ((AEP_BUILT_IN_GRANT_TYPES as readonly string[]).includes(grantType)) {
    return parseBuiltInGrantResponse(grantType, value);
  }

  if (isRecord(value)) {
    return value;
  }

  throw new TypeError("Invalid AEP Grant response.");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new TypeError(`${label} must be an object.`);
  }

  return value;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];

  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${key} must be a non-empty string.`);
  }

  return value;
}

function requireBoolean(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];

  if (typeof value !== "boolean") {
    throw new TypeError(`${key} must be a boolean.`);
  }

  return value;
}

function requireStringArray(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];

  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new TypeError(`${key} must be a string array.`);
  }

  return [...value];
}

function parseManagedAgentStatus(value: string): PlatformAgentIdentity["status"] {
  if (
    value !== "active" &&
    value !== "revoked" &&
    value !== "suspended" &&
    value !== "terminated"
  ) {
    throw new TypeError("status must be a supported managed Agent status.");
  }

  return value;
}

function isInspectServiceResult(
  value: InspectDocument | InspectServiceResult
): value is InspectServiceResult {
  return (
    isRecord(value) &&
    isRecord(value["document"]) &&
    value["inspectUrl"] instanceof URL &&
    typeof value["commandUrl"] === "function"
  );
}

function randomJti(): string {
  return `jti_${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`;
}

function credentialIdFromGrantResult(
  credential: AepBuiltInGrantResponse | Record<string, unknown>
): string {
  if (typeof credential.credential_id !== "string" || credential.credential_id.length === 0) {
    throw new TypeError("AEP Grant response does not include credential_id.");
  }

  return credential.credential_id;
}

function expiresAtFromGrantResult(
  credential: AepBuiltInGrantResponse | Record<string, unknown>
): string | undefined {
  return typeof credential.expires_at === "string" ? credential.expires_at : undefined;
}

function sessionCredentialKey(record: AepSessionCredentialRecord): string {
  return `${record.serviceDid}\u0000${record.credentialId}`;
}

function cloneCredential(record: AepSessionCredentialRecord): AepSessionCredentialRecord {
  return {
    ...record,
    credential: structuredClone(record.credential)
  };
}

function cloneAgentIdentity(identity: AgentServiceIdentity): AgentServiceIdentity {
  return {
    ...identity,
    ...(identity.metadata === undefined ? {} : { metadata: structuredClone(identity.metadata) }),
    signingAlgorithms: [...identity.signingAlgorithms]
  };
}

function cloneCachedInspect(result: CachedInspectServiceResult): CachedInspectServiceResult {
  return {
    ...result,
    document: structuredClone(result.document)
  };
}

function metadataString(metadata: Record<string, unknown>, key: string): string {
  const value = metadata[key];

  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`Platform-hosted Agent identity metadata is missing ${key}.`);
  }

  return value;
}

function isOAuthBearerGrantResponse(
  credential: AepBuiltInGrantResponse
): credential is OAuthBearerGrantResponse {
  return "access_token" in credential && credential.token_type === "Bearer";
}

function isApiKeyGrantResponse(
  credential: AepBuiltInGrantResponse
): credential is ApiKeyGrantResponse {
  return "api_key" in credential && "header" in credential;
}

function isBasicGrantResponse(
  credential: AepBuiltInGrantResponse
): credential is BasicGrantResponse {
  return "username" in credential && "password" in credential;
}

function base64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

function preferredSigningAlgorithm(algorithms: AepSigningAlgorithm[]): AepSigningAlgorithm {
  const algorithm = algorithms.find((candidate) => candidate === "ES256" || candidate === "EdDSA");

  if (algorithm === undefined) {
    throw new TypeError("AEP Service does not advertise a supported JOSE signing algorithm.");
  }

  return algorithm;
}

async function throwCommandError(response: ResponseLike, command: string): Promise<void> {
  if (response.ok) {
    return;
  }

  const problem = await readProblemDetails(response);

  throw new AepCommandError(
    `AEP ${command} failed with HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}.`,
    response.status,
    problem
  );
}

async function readProblemDetails(response: ResponseLike): Promise<AepProblemDetails | undefined> {
  try {
    return parseProblemDetails(await response.json());
  } catch {
    return undefined;
  }
}
