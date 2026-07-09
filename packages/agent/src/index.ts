import {
  AEP_AUTH_SCHEME,
  AEP_AUTHENTICATED_COMMANDS,
  AEP_BUILT_IN_GRANT_TYPES,
  AEP_MEDIA_TYPE,
  AEP_SIGNING_ALGORITHMS,
  AEP_WELL_KNOWN_PATH,
  commandPathFromInspect,
  parseBuiltInGrantResponse,
  parseClientAssertionClaims,
  parseEnrollResponse,
  parseGrantRequest,
  parseInspectDocument,
  parseProblemDetails,
  parseRevokeRequest,
  parseRevokeResponse,
  parseStatusResponse,
  signClientAssertionJwt
} from "@aep-foundation/core";
import {
  createPlatformProvisionRequest,
  createPlatformSignRequest
} from "@aep-foundation/platform";
import type {
  AepBuiltInGrantResponse,
  AepAuthenticatedCommand,
  AepClientAssertionClaims,
  AepHttpCommand,
  AepGrantType,
  AepProblemDetails,
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
  PlatformDiscoveryDocument,
  PlatformSignResponse
} from "@aep-foundation/platform";

export type Awaitable<T> = T | Promise<T>;

export interface AepClientAssertionSignerContext {
  command: AepAuthenticatedCommand;
  serviceDid: string;
  signingAlgorithms: AepSigningAlgorithm[];
}

export type AepClientAssertionSigner = (
  claims: AepClientAssertionClaims,
  context: AepClientAssertionSignerContext
) => Awaitable<string>;

export interface AepAgentOptions {
  assertionClock?: () => Date;
  assertionJti?: () => string;
  assertionTtlSeconds?: number;
  credentialStore?: AgentCredentialStore;
  identityProvider: AgentIdentityProvider;
  identityStore?: AgentIdentityStore;
  idempotencyKeys?: AgentIdempotencyKeyProvider;
  inspectCache?: AgentInspectCache;
}

export interface InspectServiceOptions {
  serviceUrl: string | URL;
}

export interface InspectServiceResult {
  document: InspectDocument;
  inspectUrl: URL;
  commandUrl(command: AepHttpCommand): URL;
  cacheControl?: string;
  etag?: string;
}

export interface DiscoverPlatformOptions {
  platformUrl: string | URL;
}

export interface DiscoverPlatformResult {
  document: PlatformDiscoveryDocument;
  discoveryUrl: URL;
  endpointUrl(endpoint: keyof PlatformDiscoveryDocument["endpoints"]): URL;
}

export interface ProvisionPlatformIdentityOptions {
  authorization?: string;
  discovery?: DiscoverPlatformResult;
  idempotencyKey: string;
  platformUrl: string | URL;
  serviceDid: string;
}

export type ProvisionPlatformIdentityResult = AepCommandResult<PlatformAgentIdentity>;

export interface PlatformDelegatedSignerOptions {
  authorization?: string;
  discovery?: DiscoverPlatformResult;
  identity: PlatformAgentIdentity;
  platformUrl: string | URL;
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
  serviceUrl: string | URL;
}

export interface EnrollServiceOptions extends AepCommandOptions {
  agentDid: string;
  claims?: Record<string, unknown>;
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
  command: AepAuthenticatedCommand;
  clock?: () => Date;
  jti?: string | (() => string);
  serviceDid: string;
  ttlSeconds?: number;
}

export interface SignClientAssertionOptions extends BuildClientAssertionClaimsOptions {
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
  command?: AepAuthenticatedCommand;
  inspect?: InspectDocument | InspectServiceResult;
  serviceDid?: string;
  signingAlgorithms?: AepSigningAlgorithm[];
}

export type ProtectedResourceAuthenticationHeadersOptions =
  | {
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
  set(serviceUrl: string, result: CachedInspectServiceResult): Awaitable<void>;
}

export interface CreatePlatformIdentityProviderOptions {
  authorization?: string;
  idempotencyKey?: string | ((input: AgentIdentityProviderGetOrCreateInput) => string);
  platformUrl: string | URL;
}

export interface AgentServiceSessionOptions {
  serviceUrl: string | URL;
}

export interface AgentEnrollSessionOptions {
  claims?: Record<string, unknown>;
  idempotencyKey?: string;
}

export interface AgentGrantSessionOptions {
  grantType?: AepGrantType;
  idempotencyKey?: string;
  parameters?: Record<string, unknown>;
  preferredGrantTypes?: AepGrantType[];
  requestedScopes?: string[];
}

export type AgentRevokeSessionOptions = RevokeServiceSelector & {
  idempotencyKey?: string;
  parameters?: Record<string, unknown>;
};

export interface AgentAuthenticationHeadersOptions {
  preferCredential?: boolean;
}

export interface AepServiceSession {
  authenticationHeaders(
    options?: AgentAuthenticationHeadersOptions
  ): Promise<Record<string, string>>;
  enroll(options?: AgentEnrollSessionOptions): Promise<EnrollServiceResult>;
  grant(options?: AgentGrantSessionOptions): Promise<GrantServiceResult>;
  identity(): Promise<AgentServiceIdentity>;
  inspect(): Promise<InspectServiceResult>;
  revoke(options: AgentRevokeSessionOptions): Promise<RevokeServiceResult>;
  status(): Promise<StatusServiceResult>;
}

export type FetchLike = (input: URL | string, init?: RequestInit) => Promise<ResponseLike>;

export interface ResponseLike {
  ok: boolean;
  status: number;
  statusText?: string;
  headers: HeadersLike;
  json(): Promise<unknown>;
}

export interface HeadersLike {
  get(name: string): string | null;
}

export class AepInspectError extends Error {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "AepInspectError";

    if (status !== undefined) {
      this.status = status;
    }
  }
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

export interface AepAgent {
  serviceSession(options: AgentServiceSessionOptions): AepServiceSession;
}

export function createAepAgent(options: AepAgentOptions): AepAgent {
  const identityStore = options.identityStore ?? createInMemoryAgentIdentityStore();
  const credentialStore = options.credentialStore ?? createInMemorySessionCredentialStore();
  const idempotencyKeys = options.idempotencyKeys ?? createRandomIdempotencyKeyProvider();
  const inspectCache = options.inspectCache ?? createInMemoryInspectCache();
  const assertionOptions = assertionOptionsWithDefinedValues(options);

  return {
    serviceSession: (sessionOptions) =>
      createAepServiceSession({
        ...assertionOptions,
        credentialStore,
        idempotencyKeys,
        identityProvider: options.identityProvider,
        identityStore,
        inspectCache,
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
  serviceUrl: string | URL;
}

function createAepServiceSession(state: AepServiceSessionState): AepServiceSession {
  const serviceUrl = normalizeServiceUrl(state.serviceUrl);
  const serviceUrlString = String(serviceUrl);
  let inspectPromise: Promise<InspectServiceResult> | undefined;
  let identityPromise: Promise<AgentServiceIdentity> | undefined;
  let signerPromise: Promise<AepClientAssertionSigner> | undefined;

  const inspectOnce = async (): Promise<InspectServiceResult> => {
    if (inspectPromise !== undefined) {
      return inspectPromise;
    }

    inspectPromise = (async () => {
      const cached = await state.inspectCache.get(serviceUrlString);

      if (cached !== undefined) {
        return cached;
      }

      const inspected = await inspectService({ serviceUrl });
      const cachedResult: CachedInspectServiceResult = {
        ...inspected,
        cachedAt: new Date().toISOString()
      };

      await state.inspectCache.set(serviceUrlString, cachedResult);
      return inspected;
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
        const credential = await state.credentialStore.findUsableCredential(
          inspected.document.service.did
        );

        if (credential !== undefined) {
          return protectedResourceAuthenticationHeaders({
            credential: parseBuiltInGrantResponse(credential.grantType, credential.credential)
          });
        }
      }

      const identity = await identityOnce();
      const signer = await signerOnce();

      return protectedResourceAuthenticationHeaders({
        agentDid: identity.agentDid,
        inspect: inspected,
        ...(state.assertionClock === undefined ? {} : { clock: state.assertionClock }),
        ...(state.assertionJti === undefined ? {} : { jti: state.assertionJti }),
        signer,
        ...(state.assertionTtlSeconds === undefined
          ? {}
          : { ttlSeconds: state.assertionTtlSeconds })
      });
    },
    async enroll(options = {}) {
      return enrollService({
        ...(await commandOptions()),
        ...assertionOptions(),
        ...(options.claims === undefined ? {} : { claims: options.claims }),
        idempotencyKey: options.idempotencyKey ?? (await idempotencyKey({ command: "enroll" }))
      });
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
      const result = await grantService({
        ...(await commandOptions()),
        ...assertionOptions(),
        grantType,
        idempotencyKey:
          options.idempotencyKey ?? (await idempotencyKey({ command: "grant", grantType })),
        ...(options.parameters === undefined ? {} : { parameters: options.parameters }),
        ...(options.requestedScopes === undefined
          ? {}
          : { requestedScopes: options.requestedScopes })
      });

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
      return statusService({
        ...(await commandOptions()),
        ...assertionOptions()
      });
    }
  };
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
  if (!AEP_AUTHENTICATED_COMMANDS.includes(options.command)) {
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
    sub: options.agentDid
  });
}

export async function signClientAssertion(options: SignClientAssertionOptions): Promise<string> {
  const claims = buildClientAssertionClaims(options);

  return options.signer(claims, {
    command: options.command,
    serviceDid: options.serviceDid,
    signingAlgorithms: [...(options.signingAlgorithms ?? AEP_SIGNING_ALGORITHMS)]
  });
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
  const fetchImpl = requireFetch();
  const platformUrl = normalizePlatformUrl(options.platformUrl);
  const discoveryUrl = new URL("/.well-known/aep-platform", platformUrl);
  const response = await fetchImpl(discoveryUrl, {
    headers: {
      Accept: AEP_MEDIA_TYPE
    }
  });

  await throwCommandError(response, "Platform discovery");

  const document = parsePlatformDiscoveryDocument(await response.json());

  return {
    document,
    discoveryUrl,
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
      platformUrl: options.platformUrl
    }));
  const commandUrl = discovery.endpointUrl("provision");
  const body = createPlatformProvisionRequest({
    idempotencyKey: options.idempotencyKey,
    serviceDid: options.serviceDid
  });
  const response = await fetchImpl(commandUrl, {
    body: JSON.stringify(body),
    headers: {
      Accept: AEP_MEDIA_TYPE,
      ...(options.authorization === undefined ? {} : { Authorization: options.authorization }),
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

export function createPlatformDelegatedSigner(
  options: PlatformDelegatedSignerOptions
): AepClientAssertionSigner {
  return async (claims) => {
    const fetchImpl = requireFetch();
    const discovery =
      options.discovery ??
      (await discoverPlatform({
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
      serviceDid: claims.aud
    });
    const response = await fetchImpl(commandUrl, {
      body: JSON.stringify(request),
      headers: {
        Accept: AEP_MEDIA_TYPE,
        ...(options.authorization === undefined ? {} : { Authorization: options.authorization }),
        "Content-Type": AEP_MEDIA_TYPE
      },
      method: "POST"
    });

    await throwCommandError(response, "Platform sign");

    return parsePlatformSignResponse(await response.json()).client_assertion;
  };
}

export function createPlatformIdentityProvider(
  options: CreatePlatformIdentityProviderOptions
): AgentIdentityProvider {
  let discoveryPromise: Promise<DiscoverPlatformResult> | undefined;

  const discovery = (): Promise<DiscoverPlatformResult> => {
    discoveryPromise ??= discoverPlatform({ platformUrl: options.platformUrl });
    return discoveryPromise;
  };

  return {
    async getOrCreateIdentity(input) {
      const platformDiscovery = await discovery();
      const idempotencyKey =
        typeof options.idempotencyKey === "function"
          ? options.idempotencyKey(input)
          : (options.idempotencyKey ?? randomJti());
      const result = await provisionPlatformIdentity({
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
      for (const [key, record] of credentials) {
        if (record.serviceDid === serviceDid && record.credentialId === credentialId) {
          credentials.delete(key);
        }
      }
    },
    findCredential(serviceDid, credentialId) {
      for (const record of credentials.values()) {
        if (record.serviceDid === serviceDid && record.credentialId === credentialId) {
          return cloneCredential(record);
        }
      }

      return undefined;
    },
    findUsableCredential(serviceDid, now = new Date()) {
      const nowMs = now.getTime();

      for (const record of credentials.values()) {
        if (record.serviceDid !== serviceDid) {
          continue;
        }

        if (record.expiresAt !== undefined && Date.parse(record.expiresAt) <= nowMs) {
          continue;
        }

        return cloneCredential(record);
      }

      return undefined;
    },
    listCredentials(serviceDid) {
      return [...credentials.values()]
        .filter((record) => record.serviceDid === serviceDid)
        .map(cloneCredential);
    },
    saveCredential(record) {
      const cloned = cloneCredential(record);
      credentials.set(sessionCredentialKey(cloned), cloned);
      return cloneCredential(cloned);
    }
  };
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
    get(serviceUrl) {
      const cached = cache.get(serviceUrl);

      return cached === undefined ? undefined : cloneCachedInspect(cached);
    },
    set(serviceUrl, result) {
      cache.set(serviceUrl, cloneCachedInspect(result));
    }
  };
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
  credential: AepBuiltInGrantResponse
): Record<string, string> {
  if (isOAuthBearerGrantResponse(credential)) {
    return {
      Authorization: `Bearer ${credential.access_token}`
    };
  }

  if (isApiKeyGrantResponse(credential)) {
    return {
      [credential.header]: credential.api_key
    };
  }

  if (isBasicGrantResponse(credential)) {
    return {
      Authorization: `Basic ${base64(`${credential.username}:${credential.password}`)}`
    };
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
    command: options.command ?? "status",
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.jti === undefined ? {} : { jti: options.jti }),
    serviceDid,
    signer: options.signer,
    ...(signingAlgorithms === undefined ? {} : { signingAlgorithms }),
    ...(options.ttlSeconds === undefined ? {} : { ttlSeconds: options.ttlSeconds })
  });

  return {
    Authorization: `${AEP_AUTH_SCHEME} ${clientAssertion}`
  };
}

export async function protectedResourceAuthenticationHeaders(
  options: ProtectedResourceAuthenticationHeadersOptions
): Promise<Record<string, string>> {
  if ("credential" in options) {
    return credentialPresentationHeaders(options.credential);
  }

  return clientAssertionAuthenticationHeaders(options);
}

export async function inspectService(
  options: InspectServiceOptions
): Promise<InspectServiceResult> {
  const fetchImpl = requireFetch();

  const serviceUrl = normalizeServiceUrl(options.serviceUrl);
  const inspectUrl = new URL(AEP_WELL_KNOWN_PATH, serviceUrl);
  const response = await fetchImpl(inspectUrl, {
    headers: {
      Accept: AEP_MEDIA_TYPE
    }
  });

  if (!response.ok) {
    throw new AepInspectError(
      `AEP Inspect failed with HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}.`,
      response.status
    );
  }

  const document = parseInspectDocument(await response.json());

  const cacheControl = response.headers.get("cache-control") ?? undefined;
  const etag = response.headers.get("etag") ?? undefined;

  return {
    document,
    inspectUrl,
    commandUrl: (command) => new URL(commandPathFromInspect(document, command), serviceUrl),
    ...(cacheControl === undefined ? {} : { cacheControl }),
    ...(etag === undefined ? {} : { etag })
  };
}

export async function enrollService(options: EnrollServiceOptions): Promise<EnrollServiceResult> {
  const fetchImpl = requireFetch();
  const inspect = await resolveInspect(options);
  const commandUrl = commandUrlFromInspect(options.serviceUrl, inspect, "enroll");
  const clientAssertion = await resolveClientAssertion(options, inspect, "enroll");
  const body = {
    agent_did: options.agentDid,
    ...(options.claims === undefined ? {} : { claims: structuredClone(options.claims) }),
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
    method: "POST"
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
  const url = serviceUrl instanceof URL ? new URL(serviceUrl) : new URL(serviceUrl);

  if (url.pathname !== "/" || url.search || url.hash) {
    url.pathname = "/";
    url.search = "";
    url.hash = "";
  }

  return url;
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

function parsePlatformSignResponse(value: unknown): PlatformSignResponse {
  const body = requireRecord(value, "Platform sign response");

  return {
    agent_did: requireString(body, "agent_did"),
    client_assertion: requireString(body, "client_assertion"),
    expires_at: requireString(body, "expires_at"),
    issued_at: requireString(body, "issued_at"),
    jti: requireString(body, "jti"),
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
      serviceUrl: options.serviceUrl
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
