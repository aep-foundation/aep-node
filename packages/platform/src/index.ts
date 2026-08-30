import {
  AEP_MEDIA_TYPE,
  AEP_PROBLEM_MEDIA_TYPE,
  AEP_SIGNING_ALGORITHMS,
  AEP_VERSION,
  createProblemDetails,
  decodeJwtUnverified,
  didWebDocumentUrl,
  isAepVersionCompatible,
  signClientAssertionJwt,
  verifyClientAssertionJwt
} from "@aep-foundation/core";
import { createHash } from "node:crypto";
import type {
  AepAssertionOperation,
  AepClientAssertionClaims,
  AepImportableJoseKey,
  AepProblemDetails,
  AepSigningAlgorithm
} from "@aep-foundation/core";

export const packageName = "@aep-foundation/platform";
export const platformHostedIdentityDraft = "draft-kavian-aep-platform-hosted-identity-01";

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
  op: AepAssertionOperation;
  resource?: string;
  sub: string;
}

export interface PlatformClientAssertionClaimsOptions {
  command: AepAssertionOperation;
  identity: ManagedAgentIdentity;
  issuedAt?: Date | number;
  jti: string;
  maxLifetimeSeconds?: number;
  serviceDid: string;
  resource?: string;
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
  op: AepAssertionOperation;
  resource?: string;
  platform_context?: Record<string, unknown>;
  service_did: string;
}

export interface PlatformSignRequestOptions {
  command: AepAssertionOperation;
  jti: string;
  maxLifetimeSeconds?: number;
  serviceDid: string;
  resource?: string;
  lifetimeSeconds?: number;
  platformContext?: Record<string, unknown>;
}

export interface PlatformSignCompletedResponse {
  status: "completed";
  agent_did: string;
  client_assertion: string;
  expires_at: string;
  issued_at: string;
  jti: string;
  platform_context?: Record<string, unknown>;
  service_did: string;
}

export interface PlatformSignPendingResponse {
  status: "pending";
  platform_context?: Record<string, unknown>;
  retry_after_seconds: string;
}

export type PlatformSignResponse = PlatformSignCompletedResponse | PlatformSignPendingResponse;

export interface PlatformSignResponseOptions {
  clientAssertion: string;
  identity: ManagedAgentIdentity;
  issuedAt?: Date | number;
  jti: string;
  maxLifetimeSeconds?: number;
  serviceDid: string;
  lifetimeSeconds?: number;
  platformContext?: Record<string, unknown>;
}

export interface PlatformSignPendingResponseOptions {
  platformContext?: Record<string, unknown>;
  retryAfterSeconds: number;
}

export interface PlatformVerificationRequest {
  client_assertion: string;
  op: AepAssertionOperation;
  resource?: string;
  service_did: string;
}

export interface PlatformVerificationRequestOptions {
  clientAssertion: string;
  command: AepAssertionOperation;
  serviceDid: string;
  resource?: string;
}

export interface PlatformVerificationResponse {
  agent_did?: string;
  agent_identity_id?: string;
  op?: AepAssertionOperation;
  reason: string;
  service_did: string;
  status?: ManagedAgentStatus;
  verified: boolean;
}

export interface PlatformVerificationResponseOptions {
  agentDid?: string;
  agentIdentityId?: string;
  command?: AepAssertionOperation;
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
  idempotencyKey?: string;
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
  descending?: boolean;
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
  findByServiceDid(
    serviceDid: string,
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

export type PlatformIdempotentOperation = "hosted_verification" | "provision" | "sign";

export interface PlatformIdempotencyRecord {
  expiresAt: string;
  fingerprint: string;
  idempotencyKey: string;
  operation: PlatformIdempotentOperation;
  principal: string;
  response: PlatformHttpResponse<unknown>;
}

export interface PlatformIdempotencyStore {
  get(
    principal: string,
    idempotencyKey: string,
    context: PlatformRequestContext
  ): Awaitable<PlatformIdempotencyRecord | undefined>;
  set(record: PlatformIdempotencyRecord, context: PlatformRequestContext): Awaitable<void>;
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

export interface PlatformSignHandlerInput {
  identity: PlatformIdentityRecord;
  request: PlatformSignRequest;
}

export type PlatformSignHandler = (
  input: PlatformSignHandlerInput,
  context: PlatformRequestContext
) => Awaitable<PlatformHttpResponse<PlatformSignResponse | AepProblemDetails> | undefined>;

export interface CreateAepPlatformOptions {
  agentDidIdGenerator?: () => string;
  authorizer?: PlatformAuthorizer;
  clock?: () => Date;
  defaultLifetimeSeconds?: number;
  didHost: string;
  didPathPrefix?: string;
  didUrlTemplate: string;
  signHandler?: PlatformSignHandler;
  discovery: Omit<
    PlatformDiscoveryDocumentOptions,
    "defaultLifetimeSeconds" | "didUrlTemplate" | "signingAlgorithms"
  >;
  idGenerator?: () => string;
  idempotencyRetentionSeconds?: number;
  idempotencyStore: PlatformIdempotencyStore;
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
  ): Promise<PlatformHttpResponse<PlatformVerificationResponse | AepProblemDetails>>;
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
  if (!options.didUrlTemplate.startsWith("https://"))
    throw new TypeError("didUrlTemplate must be an HTTPS URL template.");
  assertEndpointPath("endpointBase", options.endpointBase);
  assertEndpointPath("lifecycle endpoint", options.endpoints.lifecycle);
  assertEndpointPath("list endpoint", options.endpoints.list);
  assertNonEmpty("platformName", options.platformName);
  assertEndpointPath("provision endpoint", options.endpoints.provision);
  assertEndpointPath("sign endpoint", options.endpoints.sign);
  if (options.endpoints.hostedVerification !== undefined)
    assertEndpointPath("hosted verification endpoint", options.endpoints.hostedVerification);
  if (options.platformDid !== undefined && !options.platformDid.startsWith("did:"))
    throw new TypeError("platformDid must be a DID.");
  const aepVersion = options.aepVersion ?? AEP_VERSION;
  if (!isAepVersionCompatible(aepVersion)) {
    throw new TypeError("aepVersion must identify a supported AEP major version.");
  }
  const defaultLifetimeSeconds = options.defaultLifetimeSeconds ?? defaultAssertionLifetimeSeconds;
  validateLifetimeSeconds(defaultLifetimeSeconds, options.maxLifetimeSeconds);

  if (options.signingAlgorithms.length === 0) {
    throw new TypeError("signingAlgorithms must include at least one algorithm.");
  }
  if (
    options.signingAlgorithms.some(
      (algorithm) => !AEP_SIGNING_ALGORITHMS.some((supported) => supported === algorithm)
    )
  )
    throw new TypeError("signingAlgorithms contains an unsupported algorithm.");

  const didMethods = [...(options.didMethods ?? ["did:web"])];

  if (didMethods.length === 0) {
    throw new TypeError("didMethods must include at least one DID method.");
  }

  return {
    aep_version: aepVersion,
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
  assertNonEmpty("serviceDid", options.serviceDid);

  return {
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
  if ((options.command === "authenticate") !== (options.resource !== undefined))
    throw new TypeError("resource is required only for authenticate assertions.");

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
    ...(options.resource === undefined ? {} : { resource: options.resource }),
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
  if ((options.command === "authenticate") !== (options.resource !== undefined))
    throw new TypeError("resource is required only for authenticate signing.");
  const lifetimeSeconds =
    options.lifetimeSeconds === undefined
      ? undefined
      : validateLifetimeSeconds(options.lifetimeSeconds, options.maxLifetimeSeconds);

  return {
    jti: options.jti,
    ...(lifetimeSeconds === undefined ? {} : { lifetime_seconds: String(lifetimeSeconds) }),
    op: options.command,
    ...(options.resource === undefined ? {} : { resource: options.resource }),
    ...(options.platformContext === undefined
      ? {}
      : { platform_context: cloneRecord(options.platformContext) }),
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
    status: "completed",
    agent_did: options.identity.agentDid,
    client_assertion: options.clientAssertion,
    expires_at: epochSecondsToIso(issuedAt + lifetimeSeconds),
    issued_at: epochSecondsToIso(issuedAt),
    jti: options.jti,
    ...(options.platformContext === undefined
      ? {}
      : { platform_context: cloneRecord(options.platformContext) }),
    service_did: options.serviceDid
  };
}

export function createPlatformSignPendingResponse(
  options: PlatformSignPendingResponseOptions
): PlatformSignPendingResponse {
  if (
    !Number.isInteger(options.retryAfterSeconds) ||
    options.retryAfterSeconds < 1 ||
    options.retryAfterSeconds > 300
  ) {
    throw new RangeError("retryAfterSeconds must be an integer from 1 through 300.");
  }
  return {
    status: "pending",
    ...(options.platformContext === undefined
      ? {}
      : { platform_context: cloneRecord(options.platformContext) }),
    retry_after_seconds: String(options.retryAfterSeconds)
  };
}

export function createPlatformVerificationRequest(
  options: PlatformVerificationRequestOptions
): PlatformVerificationRequest {
  assertNonEmpty("clientAssertion", options.clientAssertion);
  assertNonEmpty("serviceDid", options.serviceDid);
  if ((options.command === "authenticate") !== (options.resource !== undefined))
    throw new TypeError("resource is required only for authenticate verification.");

  return {
    client_assertion: options.clientAssertion,
    op: options.command,
    ...(options.resource === undefined ? {} : { resource: options.resource }),
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
  const agentDidIdGenerator = options.agentDidIdGenerator ?? idGenerator;
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
      return executePlatformIdempotent<PlatformAgentIdentity | AepProblemDetails>(
        "provision",
        request,
        context,
        options.idempotencyStore,
        clock,
        options.idempotencyRetentionSeconds,
        async () => {
          if ((await authorizer.authorizeProvision?.(request, context)) === false) {
            return problem(404, "not_recognized", "Identity not recognized.");
          }

          if (!request.service_did.startsWith("did:")) {
            return problem(400, "invalid_request", "service_did must be a DID.");
          }

          if (!(await options.serviceDidResolver.resolve(request.service_did, context))) {
            return problem(400, "invalid_request", "Service DID could not be resolved.");
          }

          const existingIdentity = await options.identityStore.findByServiceDid(
            request.service_did,
            context
          );

          if (existingIdentity !== undefined) {
            return ok(200, platformIdentityFromRecord(existingIdentity));
          }

          const generatedId = idGenerator();
          assertNonEmpty("generated identity id", generatedId);
          const now = clock().toISOString();
          const agentDidId = agentDidIdGenerator();
          assertNonEmpty("generated Agent DID id", agentDidId);
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

          return ok(200, platformIdentityFromRecord(identity));
        }
      );
    },

    async sign(agentIdentityId, body, context = {}) {
      const request = parsePlatformSignRequestBody(body);
      return executePlatformIdempotent<PlatformSignResponse | AepProblemDetails>(
        "sign",
        { agent_identity_id: agentIdentityId, request },
        context,
        options.idempotencyStore,
        clock,
        options.idempotencyRetentionSeconds,
        async () => {
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

          if (options.signHandler !== undefined) {
            const handled = await options.signHandler(
              { identity: clonePlatformIdentityRecord(identity), request },
              context
            );
            if (handled !== undefined) return handled;
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
            ...(request.resource === undefined ? {} : { resource: request.resource }),
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
              ...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds }),
              ...(request.platform_context === undefined
                ? {}
                : { platformContext: request.platform_context })
            })
          );
        }
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
      return executePlatformIdempotent<PlatformVerificationResponse | AepProblemDetails>(
        "hosted_verification",
        request,
        context,
        options.idempotencyStore,
        clock,
        options.idempotencyRetentionSeconds,
        async () => {
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

            if (
              claims.op !== request.op ||
              (request.op === "authenticate"
                ? claims.resource !== request.resource
                : claims.resource !== undefined)
            ) {
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
      );
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

async function executePlatformIdempotent<TBody>(
  operation: PlatformIdempotentOperation,
  material: unknown,
  context: PlatformRequestContext,
  store: PlatformIdempotencyStore,
  clock: () => Date,
  retentionSeconds = 3600,
  execute: () => Awaitable<PlatformHttpResponse<TBody>>
): Promise<PlatformHttpResponse<TBody>> {
  const idempotencyKey = context.idempotencyKey;
  const principal = context.subject;
  if (idempotencyKey === undefined || idempotencyKey.length === 0) {
    return problem(
      400,
      "invalid_request",
      "Idempotency-Key is required."
    ) as PlatformHttpResponse<TBody>;
  }
  if (principal === undefined || principal.length === 0) {
    return problem(
      400,
      "invalid_request",
      "A stable authorized principal is required."
    ) as PlatformHttpResponse<TBody>;
  }
  if (!Number.isInteger(retentionSeconds) || retentionSeconds < 3600) {
    throw new RangeError("idempotencyRetentionSeconds must be at least 3600.");
  }

  const fingerprint = createHash("sha256").update(stableStringify(material)).digest("hex");
  const now = clock();
  const existing = await store.get(principal, idempotencyKey, context);
  if (existing !== undefined && Date.parse(existing.expiresAt) > now.getTime()) {
    if (existing.operation !== operation || existing.fingerprint !== fingerprint) {
      return problem(
        409,
        "idempotency_conflict",
        "Idempotency key already used."
      ) as PlatformHttpResponse<TBody>;
    }
    return structuredClone(existing.response) as PlatformHttpResponse<TBody>;
  }

  const response = await execute();
  await store.set(
    {
      expiresAt: new Date(now.getTime() + retentionSeconds * 1000).toISOString(),
      fingerprint,
      idempotencyKey,
      operation,
      principal,
      response: structuredClone(response)
    },
    context
  );
  return response;
}

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
    idempotencyKey: "transport-header",
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

  if (!isAssertionOperation(command)) {
    throw new TypeError("op must be an AEP assertion operation.");
  }

  const lifetimeSeconds =
    body["lifetime_seconds"] === undefined ? undefined : requireString(body, "lifetime_seconds");

  return createPlatformSignRequest({
    command,
    jti: requireString(body, "jti"),
    serviceDid: requireString(body, "service_did"),
    ...(body["resource"] === undefined ? {} : { resource: requireString(body, "resource") }),
    ...(body["platform_context"] === undefined
      ? {}
      : { platformContext: requireRecord(body["platform_context"], "platform_context") }),
    ...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds: Number(lifetimeSeconds) })
  });
}

function parsePlatformVerificationRequestBody(value: unknown): PlatformVerificationRequest {
  const body = requireRecord(value, "Platform verification request");
  const command = requireString(body, "op");

  if (!isAssertionOperation(command)) {
    throw new TypeError("op must be an AEP assertion operation.");
  }

  return createPlatformVerificationRequest({
    clientAssertion: requireString(body, "client_assertion"),
    command,
    ...(body["resource"] === undefined ? {} : { resource: requireString(body, "resource") }),
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

function isAssertionOperation(value: string): value is AepAssertionOperation {
  return (
    value === "enroll" ||
    value === "grant" ||
    value === "revoke" ||
    value === "status" ||
    value === "authenticate"
  );
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

function assertEndpointPath(label: string, value: string): void {
  if (!value.startsWith("/")) throw new TypeError(`${label} must start with '/'.`);
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
