import {
  AEP_MEDIA_TYPE,
  AEP_PROBLEM_MEDIA_TYPE,
  createProblemDetails,
  decodeJwtUnverified,
  didWebDocumentUrl,
  signClientAssertionJwt,
  verifyClientAssertionJwt
} from "@aep-foundation/core";
import type {
  AepAuthenticatedCommand,
  AepClientAssertionClaims,
  AepImportableJoseKey,
  AepProblemDetails,
  AepSigningAlgorithm
} from "@aep-foundation/core";

export const packageName = "@aep-foundation/platform";
export const platformHostedIdentityDraft = "draft-kavian-aep-platform-hosted-identity-00";

export const defaultAssertionLifetimeSeconds = 300;

export type ManagedAgentStatus = "active" | "revoked" | "suspended" | "terminated";

export interface PlatformDiscoveryDocument {
  aep_version: string;
  endpoints: {
    hosted_verification?: string;
    lifecycle: string;
    list: string;
    provision: string;
    sign: string;
    [key: string]: unknown;
  };
  http: {
    endpoint_base: string;
    [key: string]: unknown;
  };
  identity: {
    did_methods: string[];
    did_url_template: string;
    [key: string]: unknown;
  };
  platform: {
    did?: string;
    hosted_verification: boolean;
    name: string;
    [key: string]: unknown;
  };
  signing: {
    algorithms: AepSigningAlgorithm[];
    default_lifetime_seconds: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface PlatformDiscoveryDocumentOptions {
  aepVersion?: string;
  defaultLifetimeSeconds?: number;
  didMethods?: string[];
  didUrlTemplate: string;
  endpointBase: string;
  endpoints: {
    hostedVerification?: string;
    lifecycle: string;
    list: string;
    provision: string;
    sign: string;
  };
  hostedVerification?: boolean;
  maxLifetimeSeconds?: number;
  platformDid?: string;
  platformName: string;
  signingAlgorithms: AepSigningAlgorithm[];
}

export interface ManagedAgentIdentity {
  accountId?: string;
  agentDid: string;
  createdAt: string;
  metadata: Record<string, unknown>;
  status: ManagedAgentStatus;
  subjectDid?: string;
  tenantId?: string;
  updatedAt: string;
}

export interface ServiceScopedAgentDidOptions {
  agentDidId: string;
  host: string;
  pathPrefix?: string;
}

export interface PlatformAgentIdentity {
  agent_did: string;
  agent_identity_id: string;
  created_at: string;
  did_document_url: string;
  key_id: string;
  service_did: string;
  signing_algorithms: AepSigningAlgorithm[];
  status: ManagedAgentStatus;
  updated_at: string;
}

export interface PlatformPage<T> {
  count: string;
  data: T[];
  total: string;
}

export type PlatformAgentIdentityListResponse = PlatformPage<PlatformAgentIdentity>;

export interface PlatformAgentIdentityOptions {
  agentDid: string;
  agentIdentityId: string;
  clock?: () => Date;
  didDocumentUrl?: string;
  keyId?: string;
  serviceDid: string;
  signingAlgorithms: AepSigningAlgorithm[];
  status?: ManagedAgentStatus;
}

export interface ManagedAgentIdentityOptions {
  accountId?: string;
  agentDid: string;
  clock?: () => Date;
  metadata?: Record<string, unknown>;
  status?: ManagedAgentStatus;
  subjectDid?: string;
  tenantId?: string;
}

export interface ManagedAgentIdentityUpdate {
  accountId?: string;
  metadata?: Record<string, unknown>;
  status?: ManagedAgentStatus;
  subjectDid?: string;
  tenantId?: string;
}

export interface PlatformLifecycleRequest {
  status: ManagedAgentStatus;
}

export interface PlatformLifecycleRequestOptions {
  status: ManagedAgentStatus;
}

export interface ManagedAgentRegistry {
  get(agentDid: string): ManagedAgentIdentity | undefined;
  list(filter?: ManagedAgentListFilter): ManagedAgentIdentity[];
  remove(agentDid: string): boolean;
  setStatus(agentDid: string, status: ManagedAgentStatus): ManagedAgentIdentity;
  upsert(identity: ManagedAgentIdentity): ManagedAgentIdentity;
}

export interface ManagedAgentListFilter {
  accountId?: string;
  status?: ManagedAgentStatus;
  tenantId?: string;
}

export interface PlatformEnrollRequest {
  agent_did: string;
  claims?: Record<string, unknown>;
  idempotency_key: string;
}

export interface PlatformEnrollRequestOptions {
  claims?: Record<string, unknown>;
  identity: ManagedAgentIdentity;
  idempotencyKey: string;
}

export interface PlatformProvisionRequest {
  idempotency_key: string;
  service_did: string;
}

export interface PlatformProvisionRequestOptions {
  idempotencyKey: string;
  serviceDid: string;
}

export interface PlatformClientAssertionClaims {
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  jti: string;
  op: AepAuthenticatedCommand;
  sub: string;
}

export interface PlatformClientAssertionClaimsOptions {
  command: AepAuthenticatedCommand;
  identity: ManagedAgentIdentity;
  issuedAt?: Date | number;
  jti: string;
  maxLifetimeSeconds?: number;
  serviceDid: string;
  lifetimeSeconds?: number;
}

export type DidVerificationRelationship =
  | "assertionMethod"
  | "authentication"
  | "capabilityDelegation"
  | "capabilityInvocation"
  | "keyAgreement";

export interface DidVerificationMethod {
  controller: string;
  id: string;
  publicKeyJwk?: Record<string, unknown>;
  publicKeyMultibase?: string;
  publicKeyPem?: string;
  type: string;
  [key: string]: unknown;
}

export interface DidService {
  id: string;
  serviceEndpoint: string | string[] | Record<string, unknown>;
  type: string;
  [key: string]: unknown;
}

export interface DidDocument {
  "@context": string | string[];
  assertionMethod?: Array<string | DidVerificationMethod>;
  authentication?: Array<string | DidVerificationMethod>;
  capabilityDelegation?: Array<string | DidVerificationMethod>;
  capabilityInvocation?: Array<string | DidVerificationMethod>;
  controller?: string | string[];
  id: string;
  keyAgreement?: Array<string | DidVerificationMethod>;
  service?: DidService[];
  verificationMethod?: DidVerificationMethod[];
  [key: string]: unknown;
}

export interface ManagedAgentDidVerificationMethodOptions {
  controller?: string;
  id?: string;
  publicKeyJwk?: Record<string, unknown>;
  publicKeyMultibase?: string;
  publicKeyPem?: string;
  relationships?: DidVerificationRelationship[];
  type: string;
  [key: string]: unknown;
}

export interface ManagedAgentDidDocumentOptions {
  additionalContexts?: string[];
  controller?: string | string[];
  identity: ManagedAgentIdentity;
  service?: DidService[];
  verificationMethods: ManagedAgentDidVerificationMethodOptions[];
}

export interface DidDocumentPublication {
  document: DidDocument;
  publishedAt: string;
  url?: string;
}

export interface DidDocumentPublisher {
  publish(document: DidDocument): Promise<DidDocumentPublication> | DidDocumentPublication;
}

export interface PublishManagedAgentDidDocumentOptions extends ManagedAgentDidDocumentOptions {
  publisher: DidDocumentPublisher;
}

export interface PlatformDelegatedSigningContext {
  identity: ManagedAgentIdentity;
  signingAlgorithms: AepSigningAlgorithm[];
}

export type PlatformDelegatedSigner = (
  claims: AepClientAssertionClaims,
  context: PlatformDelegatedSigningContext
) => Promise<string> | string;

export interface JwtPlatformDelegatedSignerOptions {
  alg?: AepSigningAlgorithm;
  key: AepImportableJoseKey;
  kid?: string;
  typ?: string;
}

export interface SignPlatformClientAssertionOptions extends PlatformClientAssertionClaimsOptions {
  signer: PlatformDelegatedSigner;
  signingAlgorithms?: AepSigningAlgorithm[];
}

export interface PlatformSignRequest {
  jti: string;
  lifetime_seconds?: string;
  op: AepAuthenticatedCommand;
  service_did: string;
}

export interface PlatformSignRequestOptions {
  command: AepAuthenticatedCommand;
  jti: string;
  maxLifetimeSeconds?: number;
  serviceDid: string;
  lifetimeSeconds?: number;
}

export interface PlatformSignResponse {
  agent_did: string;
  client_assertion: string;
  expires_at: string;
  issued_at: string;
  jti: string;
  service_did: string;
}

export interface PlatformSignResponseOptions {
  clientAssertion: string;
  identity: ManagedAgentIdentity;
  issuedAt?: Date | number;
  jti: string;
  maxLifetimeSeconds?: number;
  serviceDid: string;
  lifetimeSeconds?: number;
}

export interface PlatformVerificationRequest {
  client_assertion: string;
  op: AepAuthenticatedCommand;
  service_did: string;
}

export interface PlatformVerificationRequestOptions {
  clientAssertion: string;
  command: AepAuthenticatedCommand;
  serviceDid: string;
}

export interface PlatformVerificationResponse {
  agent_did?: string;
  agent_identity_id?: string;
  op?: AepAuthenticatedCommand;
  reason: string;
  service_did: string;
  status?: ManagedAgentStatus;
  verified: boolean;
}

export interface PlatformVerificationResponseOptions {
  agentDid?: string;
  agentIdentityId?: string;
  command?: AepAuthenticatedCommand;
  reason: string;
  serviceDid: string;
  status?: ManagedAgentStatus;
  verified: boolean;
}

export type Awaitable<T> = T | Promise<T>;

export interface PlatformHttpResponse<TBody = unknown> {
  body: TBody;
  contentType: string;
  status: number;
}

export interface PlatformRequestContext {
  authorization?: string;
  now?: Date;
  requestId?: string;
  subject?: string;
}

export interface PlatformIdentityRecord {
  agentDid: string;
  agentDidId: string;
  agentIdentityId: string;
  createdAt: string;
  didDocumentUrl: string;
  keyId: string;
  serviceDid: string;
  signingAlgorithms: AepSigningAlgorithm[];
  status: ManagedAgentStatus;
  updatedAt: string;
}

export interface PlatformIdentityListQuery {
  limit?: number;
  offset?: number;
  serviceDid?: string;
  status?: ManagedAgentStatus;
}

export interface PlatformIdentityListResult {
  identities: PlatformIdentityRecord[];
  total: number;
}

export interface PlatformIdentityStore {
  create(identity: PlatformIdentityRecord, context: PlatformRequestContext): Awaitable<void>;
  findByAgentDid(
    agentDid: string,
    context: PlatformRequestContext
  ): Awaitable<PlatformIdentityRecord | undefined>;
  get(
    agentIdentityId: string,
    context: PlatformRequestContext
  ): Awaitable<PlatformIdentityRecord | undefined>;
  list(
    query: PlatformIdentityListQuery,
    context: PlatformRequestContext
  ): Awaitable<PlatformIdentityListResult>;
  update(
    agentIdentityId: string,
    update: { status: ManagedAgentStatus; updatedAt: string },
    context: PlatformRequestContext
  ): Awaitable<PlatformIdentityRecord | undefined>;
}

export interface PlatformProvisionIdempotencyRecord {
  idempotencyKey: string;
  requestHash: string;
  response: PlatformAgentIdentity;
}

export interface PlatformProvisionIdempotencyStore {
  get(
    idempotencyKey: string,
    context: PlatformRequestContext
  ): Awaitable<PlatformProvisionIdempotencyRecord | undefined>;
  set(record: PlatformProvisionIdempotencyRecord, context: PlatformRequestContext): Awaitable<void>;
}

export interface PlatformReplayStore {
  consume(key: string, expiresAt: Date, context: PlatformRequestContext): Awaitable<boolean>;
}

export interface PlatformKeyStore {
  create(identity: PlatformIdentityRecord, context: PlatformRequestContext): Awaitable<void>;
  didVerificationMethod(
    identity: PlatformIdentityRecord,
    context: PlatformRequestContext
  ): Awaitable<ManagedAgentDidVerificationMethodOptions>;
  sign(
    identity: PlatformIdentityRecord,
    claims: AepClientAssertionClaims,
    context: PlatformRequestContext
  ): Awaitable<string>;
  verificationKey(
    identity: PlatformIdentityRecord,
    context: PlatformRequestContext
  ): Awaitable<AepImportableJoseKey>;
}

export interface PlatformServiceDidResolver {
  resolve(serviceDid: string, context: PlatformRequestContext): Awaitable<boolean>;
}

export interface PlatformAuthorizer {
  authorizeIdentityAccess?(
    identity: PlatformIdentityRecord,
    context: PlatformRequestContext
  ): Awaitable<boolean>;
  authorizeList?(context: PlatformRequestContext): Awaitable<boolean>;
  authorizeProvision?(
    request: PlatformProvisionRequest,
    context: PlatformRequestContext
  ): Awaitable<boolean>;
}

export interface PlatformLifecyclePolicy {
  canSign(identity: PlatformIdentityRecord, context: PlatformRequestContext): Awaitable<boolean>;
  canTransition(
    identity: PlatformIdentityRecord,
    nextStatus: ManagedAgentStatus,
    context: PlatformRequestContext
  ): Awaitable<boolean>;
  canVerify(identity: PlatformIdentityRecord, context: PlatformRequestContext): Awaitable<boolean>;
}

export interface CreateAepPlatformOptions {
  authorizer?: PlatformAuthorizer;
  clock?: () => Date;
  defaultLifetimeSeconds?: number;
  didHost: string;
  didPathPrefix?: string;
  didUrlTemplate: string;
  discovery: Omit<
    PlatformDiscoveryDocumentOptions,
    "defaultLifetimeSeconds" | "didUrlTemplate" | "signingAlgorithms"
  >;
  idGenerator?: () => string;
  idempotencyStore: PlatformProvisionIdempotencyStore;
  identityStore: PlatformIdentityStore;
  keyStore: PlatformKeyStore;
  lifecyclePolicy?: PlatformLifecyclePolicy;
  maxLifetimeSeconds?: number;
  replayStore: PlatformReplayStore;
  serviceDidResolver: PlatformServiceDidResolver;
  signingAlgorithms: AepSigningAlgorithm[];
}

export interface AepPlatform {
  discovery(): PlatformHttpResponse<PlatformDiscoveryDocument>;
  getDidDocument(
    agentIdentityId: string,
    context?: PlatformRequestContext
  ): Promise<PlatformHttpResponse<DidDocument | AepProblemDetails>>;
  getIdentity(
    agentIdentityId: string,
    context?: PlatformRequestContext
  ): Promise<PlatformHttpResponse<PlatformAgentIdentity | AepProblemDetails>>;
  list(
    query?: PlatformIdentityListQuery,
    context?: PlatformRequestContext
  ): Promise<PlatformHttpResponse<PlatformAgentIdentityListResponse | AepProblemDetails>>;
  provision(
    body: unknown,
    context?: PlatformRequestContext
  ): Promise<PlatformHttpResponse<PlatformAgentIdentity | AepProblemDetails>>;
  sign(
    agentIdentityId: string,
    body: unknown,
    context?: PlatformRequestContext
  ): Promise<PlatformHttpResponse<PlatformSignResponse | AepProblemDetails>>;
  updateIdentity(
    agentIdentityId: string,
    body: unknown,
    context?: PlatformRequestContext
  ): Promise<PlatformHttpResponse<PlatformAgentIdentity | AepProblemDetails>>;
  verify(
    body: unknown,
    context?: PlatformRequestContext
  ): Promise<PlatformHttpResponse<PlatformVerificationResponse>>;
}

export class InMemoryManagedAgentRegistry implements ManagedAgentRegistry {
  readonly #identities = new Map<string, ManagedAgentIdentity>();

  constructor(identities: ManagedAgentIdentity[] = []) {
    identities.forEach((identity) => this.upsert(identity));
  }

  get(agentDid: string): ManagedAgentIdentity | undefined {
    const identity = this.#identities.get(agentDid);
    return identity === undefined ? undefined : cloneManagedAgentIdentity(identity);
  }

  list(filter: ManagedAgentListFilter = {}): ManagedAgentIdentity[] {
    return Array.from(this.#identities.values())
      .filter(
        (identity) => filter.accountId === undefined || identity.accountId === filter.accountId
      )
      .filter((identity) => filter.status === undefined || identity.status === filter.status)
      .filter((identity) => filter.tenantId === undefined || identity.tenantId === filter.tenantId)
      .map(cloneManagedAgentIdentity);
  }

  remove(agentDid: string): boolean {
    return this.#identities.delete(agentDid);
  }

  setStatus(agentDid: string, status: ManagedAgentStatus): ManagedAgentIdentity {
    const identity = this.#identities.get(agentDid);

    if (identity === undefined) {
      throw new Error(`Managed Agent identity not found: ${agentDid}.`);
    }

    const updated = {
      ...identity,
      status,
      updatedAt: new Date().toISOString()
    };

    this.#identities.set(agentDid, updated);
    return cloneManagedAgentIdentity(updated);
  }

  upsert(identity: ManagedAgentIdentity): ManagedAgentIdentity {
    assertNonEmpty("agentDid", identity.agentDid);
    const cloned = cloneManagedAgentIdentity(identity);
    this.#identities.set(cloned.agentDid, cloned);
    return cloneManagedAgentIdentity(cloned);
  }
}

export function createManagedAgentIdentity(
  options: ManagedAgentIdentityOptions
): ManagedAgentIdentity {
  assertNonEmpty("agentDid", options.agentDid);
  const now = (options.clock ?? (() => new Date()))().toISOString();

  return {
    agentDid: options.agentDid,
    createdAt: now,
    metadata: structuredClone(options.metadata ?? {}),
    status: options.status ?? "active",
    updatedAt: now,
    ...(options.accountId === undefined ? {} : { accountId: options.accountId }),
    ...(options.subjectDid === undefined ? {} : { subjectDid: options.subjectDid }),
    ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId })
  };
}

export function updateManagedAgentIdentity(
  identity: ManagedAgentIdentity,
  update: ManagedAgentIdentityUpdate,
  clock: () => Date = () => new Date()
): ManagedAgentIdentity {
  return {
    ...cloneManagedAgentIdentity(identity),
    ...update,
    metadata:
      update.metadata === undefined
        ? cloneRecord(identity.metadata)
        : {
            ...cloneRecord(identity.metadata),
            ...cloneRecord(update.metadata)
          },
    updatedAt: clock().toISOString()
  };
}

export function createPlatformDiscoveryDocument(
  options: PlatformDiscoveryDocumentOptions
): PlatformDiscoveryDocument {
  assertNonEmpty("didUrlTemplate", options.didUrlTemplate);
  assertNonEmpty("endpointBase", options.endpointBase);
  assertNonEmpty("lifecycle endpoint", options.endpoints.lifecycle);
  assertNonEmpty("list endpoint", options.endpoints.list);
  assertNonEmpty("platformName", options.platformName);
  assertNonEmpty("provision endpoint", options.endpoints.provision);
  assertNonEmpty("sign endpoint", options.endpoints.sign);
  const defaultLifetimeSeconds = options.defaultLifetimeSeconds ?? defaultAssertionLifetimeSeconds;
  validateLifetimeSeconds(defaultLifetimeSeconds, options.maxLifetimeSeconds);

  if (options.signingAlgorithms.length === 0) {
    throw new TypeError("signingAlgorithms must include at least one algorithm.");
  }

  const didMethods = [...(options.didMethods ?? ["did:web"])];

  if (didMethods.length === 0) {
    throw new TypeError("didMethods must include at least one DID method.");
  }

  return {
    aep_version: options.aepVersion ?? "1.0",
    endpoints: {
      ...(options.endpoints.hostedVerification === undefined
        ? {}
        : { hosted_verification: options.endpoints.hostedVerification }),
      lifecycle: options.endpoints.lifecycle,
      list: options.endpoints.list,
      provision: options.endpoints.provision,
      sign: options.endpoints.sign
    },
    http: {
      endpoint_base: options.endpointBase
    },
    identity: {
      did_methods: didMethods,
      did_url_template: options.didUrlTemplate
    },
    platform: {
      ...(options.platformDid === undefined ? {} : { did: options.platformDid }),
      hosted_verification: options.hostedVerification ?? false,
      name: options.platformName
    },
    signing: {
      algorithms: [...options.signingAlgorithms],
      default_lifetime_seconds: String(defaultLifetimeSeconds)
    }
  };
}

export function createServiceScopedAgentDid(options: ServiceScopedAgentDidOptions): string {
  assertNonEmpty("agentDidId", options.agentDidId);
  assertNonEmpty("host", options.host);
  const encodedHost = encodeURIComponent(options.host);
  const pathPrefix = options.pathPrefix ?? "agents";
  const pathParts = pathPrefix
    .split("/")
    .filter((part) => part.length > 0)
    .map((part) => encodeURIComponent(part));

  return ["did:web", encodedHost, ...pathParts, encodeURIComponent(options.agentDidId)].join(":");
}

export function createPlatformAgentIdentity(
  options: PlatformAgentIdentityOptions
): PlatformAgentIdentity {
  assertNonEmpty("agentDid", options.agentDid);
  assertNonEmpty("agentIdentityId", options.agentIdentityId);
  assertNonEmpty("serviceDid", options.serviceDid);

  if (options.signingAlgorithms.length === 0) {
    throw new TypeError("signingAlgorithms must include at least one algorithm.");
  }

  const now = (options.clock ?? (() => new Date()))().toISOString();
  const keyId = options.keyId ?? options.agentDid;

  return {
    agent_did: options.agentDid,
    agent_identity_id: options.agentIdentityId,
    created_at: now,
    did_document_url: options.didDocumentUrl ?? didWebDocumentUrl(options.agentDid).toString(),
    key_id: keyId,
    service_did: options.serviceDid,
    signing_algorithms: [...options.signingAlgorithms],
    status: options.status ?? "active",
    updated_at: now
  };
}

export function createPlatformAgentIdentityListResponse(
  identities: PlatformAgentIdentity[],
  total = identities.length
): PlatformAgentIdentityListResponse {
  return {
    count: String(identities.length),
    data: identities.map((identity) => structuredClone(identity)),
    total: String(total)
  };
}

export function createPlatformLifecycleRequest(
  options: PlatformLifecycleRequestOptions
): PlatformLifecycleRequest {
  return {
    status: options.status
  };
}

export function createPlatformProvisionRequest(
  options: PlatformProvisionRequestOptions
): PlatformProvisionRequest {
  assertNonEmpty("idempotencyKey", options.idempotencyKey);
  assertNonEmpty("serviceDid", options.serviceDid);

  return {
    idempotency_key: options.idempotencyKey,
    service_did: options.serviceDid
  };
}

export function createPlatformEnrollRequest(
  options: PlatformEnrollRequestOptions
): PlatformEnrollRequest {
  assertUsableIdentity(options.identity);
  assertNonEmpty("idempotencyKey", options.idempotencyKey);

  return {
    agent_did: options.identity.agentDid,
    ...(options.claims === undefined ? {} : { claims: cloneRecord(options.claims) }),
    idempotency_key: options.idempotencyKey
  };
}

export function createPlatformClientAssertionClaims(
  options: PlatformClientAssertionClaimsOptions
): AepClientAssertionClaims {
  assertUsableIdentity(options.identity);
  assertNonEmpty("serviceDid", options.serviceDid);
  assertNonEmpty("jti", options.jti);

  const issuedAt = toEpochSeconds(options.issuedAt ?? new Date());
  const lifetimeSeconds = validateLifetimeSeconds(
    options.lifetimeSeconds ?? defaultAssertionLifetimeSeconds,
    options.maxLifetimeSeconds
  );

  return {
    aud: options.serviceDid,
    exp: issuedAt + lifetimeSeconds,
    iat: issuedAt,
    iss: options.identity.agentDid,
    jti: options.jti,
    op: options.command,
    sub: options.identity.agentDid
  };
}

export function createManagedAgentDidDocument(
  options: ManagedAgentDidDocumentOptions
): DidDocument {
  assertUsableIdentity(options.identity);

  if (options.verificationMethods.length === 0) {
    throw new TypeError("verificationMethods must include at least one method.");
  }

  const document: DidDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", ...(options.additionalContexts ?? [])],
    id: options.identity.agentDid,
    ...(options.controller === undefined ? {} : { controller: options.controller }),
    verificationMethod: options.verificationMethods.map((method, index) =>
      createDidVerificationMethod(options.identity.agentDid, method, index)
    ),
    ...(options.service === undefined ? {} : { service: options.service.map(cloneDidService) })
  };

  for (const relationship of relationshipNames()) {
    const methodIds = document.verificationMethod
      ?.filter((method, index) =>
        (options.verificationMethods[index]?.relationships ?? ["authentication"]).includes(
          relationship
        )
      )
      .map((method) => method.id);

    if (methodIds !== undefined && methodIds.length > 0) {
      document[relationship] = methodIds;
    }
  }

  return document;
}

export async function publishManagedAgentDidDocument(
  options: PublishManagedAgentDidDocumentOptions
): Promise<DidDocumentPublication> {
  const document = createManagedAgentDidDocument(options);

  return options.publisher.publish(document);
}

export function createJwtPlatformDelegatedSigner(
  options: JwtPlatformDelegatedSignerOptions
): PlatformDelegatedSigner {
  return (claims, context) =>
    signClientAssertionJwt(claims, {
      alg: options.alg ?? preferredSigningAlgorithm(context.signingAlgorithms),
      key: options.key,
      ...(options.kid === undefined ? {} : { kid: options.kid }),
      ...(options.typ === undefined ? {} : { typ: options.typ })
    });
}

export async function signPlatformClientAssertion(
  options: SignPlatformClientAssertionOptions
): Promise<string> {
  const claims = createPlatformClientAssertionClaims(options);

  return options.signer(claims, {
    identity: options.identity,
    signingAlgorithms: [...(options.signingAlgorithms ?? ["EdDSA", "ES256"])]
  });
}

export function createPlatformSignRequest(
  options: PlatformSignRequestOptions
): PlatformSignRequest {
  assertNonEmpty("jti", options.jti);
  assertNonEmpty("serviceDid", options.serviceDid);
  const lifetimeSeconds =
    options.lifetimeSeconds === undefined
      ? undefined
      : validateLifetimeSeconds(options.lifetimeSeconds, options.maxLifetimeSeconds);

  return {
    jti: options.jti,
    ...(lifetimeSeconds === undefined ? {} : { lifetime_seconds: String(lifetimeSeconds) }),
    op: options.command,
    service_did: options.serviceDid
  };
}

export function createPlatformSignResponse(
  options: PlatformSignResponseOptions
): PlatformSignResponse {
  assertUsableIdentity(options.identity);
  assertNonEmpty("clientAssertion", options.clientAssertion);
  assertNonEmpty("jti", options.jti);
  assertNonEmpty("serviceDid", options.serviceDid);
  const issuedAt = toEpochSeconds(options.issuedAt ?? new Date());
  const lifetimeSeconds = validateLifetimeSeconds(
    options.lifetimeSeconds ?? defaultAssertionLifetimeSeconds,
    options.maxLifetimeSeconds
  );

  return {
    agent_did: options.identity.agentDid,
    client_assertion: options.clientAssertion,
    expires_at: epochSecondsToIso(issuedAt + lifetimeSeconds),
    issued_at: epochSecondsToIso(issuedAt),
    jti: options.jti,
    service_did: options.serviceDid
  };
}

export function createPlatformVerificationRequest(
  options: PlatformVerificationRequestOptions
): PlatformVerificationRequest {
  assertNonEmpty("clientAssertion", options.clientAssertion);
  assertNonEmpty("serviceDid", options.serviceDid);

  return {
    client_assertion: options.clientAssertion,
    op: options.command,
    service_did: options.serviceDid
  };
}

export function createPlatformVerificationResponse(
  options: PlatformVerificationResponseOptions
): PlatformVerificationResponse {
  assertNonEmpty("reason", options.reason);
  assertNonEmpty("serviceDid", options.serviceDid);

  return {
    ...(options.agentDid === undefined ? {} : { agent_did: options.agentDid }),
    ...(options.agentIdentityId === undefined
      ? {}
      : { agent_identity_id: options.agentIdentityId }),
    ...(options.command === undefined ? {} : { op: options.command }),
    reason: options.reason,
    service_did: options.serviceDid,
    ...(options.status === undefined ? {} : { status: options.status }),
    verified: options.verified
  };
}

export function createAepPlatform(options: CreateAepPlatformOptions): AepPlatform {
  assertNonEmpty("didHost", options.didHost);
  assertNonEmpty("didUrlTemplate", options.didUrlTemplate);

  if (options.signingAlgorithms.length === 0) {
    throw new TypeError("signingAlgorithms must include at least one algorithm.");
  }

  const clock = options.clock ?? (() => new Date());
  const idGenerator = options.idGenerator ?? randomPlatformId;
  const lifecyclePolicy = options.lifecyclePolicy ?? defaultLifecyclePolicy;
  const authorizer = options.authorizer ?? {};

  const discoveryDocument = createPlatformDiscoveryDocument({
    ...options.discovery,
    defaultLifetimeSeconds: options.defaultLifetimeSeconds ?? defaultAssertionLifetimeSeconds,
    didUrlTemplate: options.didUrlTemplate,
    signingAlgorithms: options.signingAlgorithms
  });

  return {
    discovery() {
      return ok(200, discoveryDocument);
    },

    async getDidDocument(agentIdentityId, context = {}) {
      const identity = await authorizedIdentity(
        agentIdentityId,
        authorizer,
        options.identityStore,
        context
      );

      if (identity === undefined) {
        return problem(404, "not_recognized", "Identity not recognized.");
      }

      const verificationMethod = await options.keyStore.didVerificationMethod(identity, context);

      return ok(
        200,
        createManagedAgentDidDocument({
          identity: managedIdentityFromRecord(identity),
          verificationMethods: [verificationMethod]
        })
      );
    },

    async getIdentity(agentIdentityId, context = {}) {
      const identity = await authorizedIdentity(
        agentIdentityId,
        authorizer,
        options.identityStore,
        context
      );

      if (identity === undefined) {
        return problem(404, "not_recognized", "Identity not recognized.");
      }

      return ok(200, platformIdentityFromRecord(identity));
    },

    async list(query = {}, context = {}) {
      if ((await authorizer.authorizeList?.(context)) === false) {
        return problem(404, "not_recognized", "Identity not recognized.");
      }

      const result = await options.identityStore.list(query, context);

      return ok(
        200,
        createPlatformAgentIdentityListResponse(
          result.identities.map(platformIdentityFromRecord),
          result.total
        )
      );
    },

    async provision(body, context = {}) {
      const request = parsePlatformProvisionRequestBody(body);

      if ((await authorizer.authorizeProvision?.(request, context)) === false) {
        return problem(404, "not_recognized", "Identity not recognized.");
      }

      if (!(await options.serviceDidResolver.resolve(request.service_did, context))) {
        return problem(400, "invalid_request", "Service DID could not be resolved.");
      }

      const requestHash = stableStringify(request);
      const existing = await options.idempotencyStore.get(request.idempotency_key, context);

      if (existing !== undefined) {
        if (existing.requestHash !== requestHash) {
          return problem(409, "idempotency_conflict", "Idempotency key already used.");
        }

        return ok(200, existing.response);
      }

      const generatedId = idGenerator();
      assertNonEmpty("generated identity id", generatedId);
      const now = clock().toISOString();
      const agentDidId = generatedId;
      const agentDid = createServiceScopedAgentDid({
        agentDidId,
        host: options.didHost,
        pathPrefix: options.didPathPrefix ?? "agents"
      });
      const identity: PlatformIdentityRecord = {
        agentDid,
        agentDidId,
        agentIdentityId: generatedId.startsWith("pai_") ? generatedId : `pai_${generatedId}`,
        createdAt: now,
        didDocumentUrl: renderDidUrlTemplate(options.didUrlTemplate, agentDidId),
        keyId: agentDid,
        serviceDid: request.service_did,
        signingAlgorithms: [...options.signingAlgorithms],
        status: "active",
        updatedAt: now
      };

      await options.keyStore.create(identity, context);
      await options.identityStore.create(identity, context);

      const response = platformIdentityFromRecord(identity);
      await options.idempotencyStore.set(
        {
          idempotencyKey: request.idempotency_key,
          requestHash,
          response
        },
        context
      );

      return ok(200, response);
    },

    async sign(agentIdentityId, body, context = {}) {
      const request = parsePlatformSignRequestBody(body);
      const identity = await authorizedIdentity(
        agentIdentityId,
        authorizer,
        options.identityStore,
        context
      );

      if (identity === undefined || identity.serviceDid !== request.service_did) {
        return problem(404, "not_recognized", "Identity not recognized.");
      }

      if (!(await lifecyclePolicy.canSign(identity, context))) {
        return problem(403, lifecycleProblemCode(identity.status), "Identity cannot sign.");
      }

      if (!(await options.serviceDidResolver.resolve(request.service_did, context))) {
        return problem(400, "invalid_request", "Service DID could not be resolved.");
      }

      const issuedAt = context.now ?? clock();
      const lifetimeSeconds =
        request.lifetime_seconds === undefined ? undefined : Number(request.lifetime_seconds);
      const managedIdentity = managedIdentityFromRecord(identity);
      const claims = createPlatformClientAssertionClaims({
        command: request.op,
        identity: managedIdentity,
        issuedAt,
        jti: request.jti,
        ...(options.maxLifetimeSeconds === undefined
          ? {}
          : { maxLifetimeSeconds: options.maxLifetimeSeconds }),
        serviceDid: request.service_did,
        ...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds })
      });
      const clientAssertion = await options.keyStore.sign(identity, claims, context);

      return ok(
        200,
        createPlatformSignResponse({
          clientAssertion,
          identity: managedIdentity,
          issuedAt,
          jti: request.jti,
          ...(options.maxLifetimeSeconds === undefined
            ? {}
            : { maxLifetimeSeconds: options.maxLifetimeSeconds }),
          serviceDid: request.service_did,
          ...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds })
        })
      );
    },

    async updateIdentity(agentIdentityId, body, context = {}) {
      const request = parsePlatformLifecycleRequestBody(body);
      const identity = await authorizedIdentity(
        agentIdentityId,
        authorizer,
        options.identityStore,
        context
      );

      if (identity === undefined) {
        return problem(404, "not_recognized", "Identity not recognized.");
      }

      if (!(await lifecyclePolicy.canTransition(identity, request.status, context))) {
        return problem(
          403,
          lifecycleProblemCode(identity.status),
          "Lifecycle transition rejected."
        );
      }

      const updated = await options.identityStore.update(
        agentIdentityId,
        {
          status: request.status,
          updatedAt: clock().toISOString()
        },
        context
      );

      if (updated === undefined) {
        return problem(404, "not_recognized", "Identity not recognized.");
      }

      return ok(200, platformIdentityFromRecord(updated));
    },

    async verify(body, context = {}) {
      const request = parsePlatformVerificationRequestBody(body);

      try {
        const decoded = decodeJwtUnverified(request.client_assertion);
        const agentDid = requireString(decoded.payload, "iss");
        const subject = requireString(decoded.payload, "sub");
        const jti = requireString(decoded.payload, "jti");
        const expiresAt = requireNumber(decoded.payload, "exp");

        if (agentDid !== subject) {
          return ok(200, unrecognizedVerification(request, "not_recognized"));
        }

        const identity = await options.identityStore.findByAgentDid(agentDid, context);

        if (
          identity === undefined ||
          identity.serviceDid !== request.service_did ||
          !(await lifecyclePolicy.canVerify(identity, context))
        ) {
          return ok(200, unrecognizedVerification(request, "not_recognized"));
        }

        const claims = await verifyClientAssertionJwt(request.client_assertion, {
          algorithms: identity.signingAlgorithms,
          audience: request.service_did,
          currentDate: context.now ?? clock(),
          issuer: agentDid,
          key: await options.keyStore.verificationKey(identity, context),
          subject: agentDid
        });

        if (claims.op !== request.op) {
          return ok(200, unrecognizedVerification(request, "not_recognized"));
        }

        const replayKey = [request.service_did, request.op, agentDid, jti].join("\u001f");
        const consumed = await options.replayStore.consume(
          replayKey,
          new Date(expiresAt * 1000),
          context
        );

        if (!consumed) {
          return ok(200, unrecognizedVerification(request, "not_recognized"));
        }

        return ok(
          200,
          createPlatformVerificationResponse({
            agentDid: identity.agentDid,
            agentIdentityId: identity.agentIdentityId,
            command: request.op,
            reason: "verified",
            serviceDid: request.service_did,
            status: identity.status,
            verified: true
          })
        );
      } catch {
        return ok(200, unrecognizedVerification(request, "not_recognized"));
      }
    }
  };
}

const defaultLifecyclePolicy: PlatformLifecyclePolicy = {
  canSign(identity) {
    return identity.status === "active";
  },
  canTransition() {
    return true;
  },
  canVerify(identity) {
    return identity.status === "active";
  }
};

function ok<TBody>(status: number, body: TBody): PlatformHttpResponse<TBody> {
  return {
    body,
    contentType: AEP_MEDIA_TYPE,
    status
  };
}

function problem(
  status: number,
  code: AepProblemDetails["code"],
  title: string
): PlatformHttpResponse<AepProblemDetails> {
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

async function authorizedIdentity(
  agentIdentityId: string,
  authorizer: PlatformAuthorizer,
  store: PlatformIdentityStore,
  context: PlatformRequestContext
): Promise<PlatformIdentityRecord | undefined> {
  const identity = await store.get(agentIdentityId, context);

  if (identity === undefined) {
    return undefined;
  }

  if ((await authorizer.authorizeIdentityAccess?.(identity, context)) === false) {
    return undefined;
  }

  return clonePlatformIdentityRecord(identity);
}

function platformIdentityFromRecord(identity: PlatformIdentityRecord): PlatformAgentIdentity {
  return {
    agent_did: identity.agentDid,
    agent_identity_id: identity.agentIdentityId,
    created_at: identity.createdAt,
    did_document_url: identity.didDocumentUrl,
    key_id: identity.keyId,
    service_did: identity.serviceDid,
    signing_algorithms: [...identity.signingAlgorithms],
    status: identity.status,
    updated_at: identity.updatedAt
  };
}

function managedIdentityFromRecord(identity: PlatformIdentityRecord): ManagedAgentIdentity {
  return {
    agentDid: identity.agentDid,
    createdAt: identity.createdAt,
    metadata: {
      agent_did_id: identity.agentDidId,
      agent_identity_id: identity.agentIdentityId,
      did_document_url: identity.didDocumentUrl,
      key_id: identity.keyId,
      service_did: identity.serviceDid
    },
    status: identity.status,
    updatedAt: identity.updatedAt
  };
}

function clonePlatformIdentityRecord(identity: PlatformIdentityRecord): PlatformIdentityRecord {
  return {
    ...identity,
    signingAlgorithms: [...identity.signingAlgorithms]
  };
}

function parsePlatformProvisionRequestBody(value: unknown): PlatformProvisionRequest {
  const body = requireRecord(value, "Platform provision request");

  return createPlatformProvisionRequest({
    idempotencyKey: requireString(body, "idempotency_key"),
    serviceDid: requireString(body, "service_did")
  });
}

function parsePlatformLifecycleRequestBody(value: unknown): PlatformLifecycleRequest {
  const body = requireRecord(value, "Platform lifecycle request");
  const status = requireString(body, "status");

  if (!isManagedAgentStatus(status)) {
    throw new TypeError("status must be a supported managed Agent status.");
  }

  return createPlatformLifecycleRequest({ status });
}

function parsePlatformSignRequestBody(value: unknown): PlatformSignRequest {
  const body = requireRecord(value, "Platform sign request");
  const command = requireString(body, "op");

  if (!isAuthenticatedCommand(command)) {
    throw new TypeError("op must be an AEP authenticated command.");
  }

  const lifetimeSeconds =
    body["lifetime_seconds"] === undefined ? undefined : requireString(body, "lifetime_seconds");

  return createPlatformSignRequest({
    command,
    jti: requireString(body, "jti"),
    serviceDid: requireString(body, "service_did"),
    ...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds: Number(lifetimeSeconds) })
  });
}

function parsePlatformVerificationRequestBody(value: unknown): PlatformVerificationRequest {
  const body = requireRecord(value, "Platform verification request");
  const command = requireString(body, "op");

  if (!isAuthenticatedCommand(command)) {
    throw new TypeError("op must be an AEP authenticated command.");
  }

  return createPlatformVerificationRequest({
    clientAssertion: requireString(body, "client_assertion"),
    command,
    serviceDid: requireString(body, "service_did")
  });
}

function unrecognizedVerification(
  request: PlatformVerificationRequest,
  reason: string
): PlatformVerificationResponse {
  return createPlatformVerificationResponse({
    reason,
    serviceDid: request.service_did,
    verified: false
  });
}

function renderDidUrlTemplate(template: string, agentDidId: string): string {
  if (!template.includes("{agent_did_id}")) {
    throw new TypeError("didUrlTemplate must include {agent_did_id}.");
  }

  return template.replace("{agent_did_id}", encodeURIComponent(agentDidId));
}

function lifecycleProblemCode(status: ManagedAgentStatus): AepProblemDetails["code"] {
  if (status === "terminated") {
    return "identity_terminated";
  }

  if (status === "suspended" || status === "revoked") {
    return "identity_suspended";
  }

  return "identity_unavailable";
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  if (typeof value === "object" && value !== null) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

function randomPlatformId(): string {
  return globalThis.crypto.randomUUID().replaceAll("-", "");
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }

  return value as Record<string, unknown>;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];

  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${key} must be a non-empty string.`);
  }

  return value;
}

function requireNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];

  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`${key} must be an integer.`);
  }

  return value;
}

function isAuthenticatedCommand(value: string): value is AepAuthenticatedCommand {
  return value === "enroll" || value === "grant" || value === "revoke" || value === "status";
}

function isManagedAgentStatus(value: string): value is ManagedAgentStatus {
  return (
    value === "active" || value === "revoked" || value === "suspended" || value === "terminated"
  );
}

function assertUsableIdentity(identity: ManagedAgentIdentity): void {
  assertNonEmpty("agentDid", identity.agentDid);

  if (identity.status !== "active") {
    throw new Error(`Managed Agent identity is not active: ${identity.agentDid}.`);
  }
}

function assertNonEmpty(label: string, value: string): void {
  if (value.trim().length === 0) {
    throw new TypeError(`${label} must be a non-empty string.`);
  }
}

function cloneManagedAgentIdentity(identity: ManagedAgentIdentity): ManagedAgentIdentity {
  return {
    ...identity,
    metadata: cloneRecord(identity.metadata)
  };
}

function cloneRecord(record: Record<string, unknown>): Record<string, unknown> {
  return structuredClone(record);
}

function toEpochSeconds(value: Date | number): number {
  const epochSeconds = typeof value === "number" ? value : Math.floor(value.getTime() / 1000);

  if (!Number.isInteger(epochSeconds) || epochSeconds < 0) {
    throw new TypeError("issuedAt must resolve to a non-negative epoch second.");
  }

  return epochSeconds;
}

function epochSecondsToIso(value: number): string {
  return new Date(value * 1000).toISOString();
}

function validateLifetimeSeconds(
  lifetimeSeconds: number,
  maxLifetimeSeconds = defaultAssertionLifetimeSeconds
): number {
  if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds <= 0) {
    throw new TypeError("lifetimeSeconds must be a positive integer.");
  }

  if (!Number.isInteger(maxLifetimeSeconds) || maxLifetimeSeconds <= 0) {
    throw new TypeError("maxLifetimeSeconds must be a positive integer.");
  }

  if (lifetimeSeconds > maxLifetimeSeconds) {
    throw new TypeError("lifetimeSeconds must not exceed maxLifetimeSeconds.");
  }

  return lifetimeSeconds;
}

function createDidVerificationMethod(
  agentDid: string,
  method: ManagedAgentDidVerificationMethodOptions,
  index: number
): DidVerificationMethod {
  const id = method.id ?? `${agentDid}#key-${index + 1}`;
  const controller = method.controller ?? agentDid;
  const methodBody = { ...method };
  delete methodBody.relationships;

  assertNonEmpty("verification method id", id);
  assertNonEmpty("verification method type", method.type);
  assertNonEmpty("verification method controller", controller);

  return {
    ...structuredClone(methodBody),
    controller,
    id,
    type: method.type
  };
}

function cloneDidService(service: DidService): DidService {
  return structuredClone(service);
}

function relationshipNames(): DidVerificationRelationship[] {
  return [
    "authentication",
    "assertionMethod",
    "capabilityInvocation",
    "capabilityDelegation",
    "keyAgreement"
  ];
}

function preferredSigningAlgorithm(algorithms: AepSigningAlgorithm[]): AepSigningAlgorithm {
  const algorithm = algorithms.find((candidate) => candidate === "ES256" || candidate === "EdDSA");

  if (algorithm === undefined) {
    throw new TypeError("No supported AEP JOSE signing algorithm is available.");
  }

  return algorithm;
}
