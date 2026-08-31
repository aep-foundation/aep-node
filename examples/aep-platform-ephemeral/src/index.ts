import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { AEP_MEDIA_TYPE, didWebDocumentUrl } from "@aep-foundation/core";
import express from "express";
import type { Request, Response } from "express";

import {
  createAepPlatform,
  createJwtPlatformDelegatedSigner,
  createManagedAgentDidDocument,
  createManagedAgentIdentity
} from "@aep-foundation/platform";
import type {
  DidDocument,
  ManagedAgentDidVerificationMethodOptions,
  PlatformAgentIdentity,
  PlatformHttpResponse,
  PlatformIdentityListQuery,
  PlatformIdentityListResult,
  PlatformIdentityRecord,
  PlatformIdentityStore,
  PlatformKeyStore,
  PlatformIdempotencyRecord,
  PlatformIdempotencyStore,
  PlatformReplayStore,
  PlatformRequestContext,
  PlatformSignResponse,
  PlatformVerificationResponse
} from "@aep-foundation/platform";

import { parsePort } from "../../_shared/aep-examples.js";

const host = process.env["HOST"] ?? "127.0.0.1";
const port = parsePort(process.env["PORT"] ?? "4100");
const publicBaseUrl = process.env["PUBLIC_BASE_URL"] ?? `http://${host}:${port}`;
const didHost = process.env["DID_HOST"] ?? new URL(publicBaseUrl).host;
const didUrlTemplate =
  process.env["DID_URL_TEMPLATE"] ?? `https://${didHost}/agents/{agent_did_id}/did.json`;
const encodedHost = encodeURIComponent(didHost);
const platformDid = `did:web:${encodedHost}`;
const serviceDid = `did:web:${encodedHost}:services:example-service`;
const demoAuthorization = process.env["PLATFORM_AUTHORIZATION"] ?? "Bearer demo-agent";

class ExampleIdentityStore implements PlatformIdentityStore {
  readonly #identities = new Map<string, PlatformIdentityRecord>();

  create(identity: PlatformIdentityRecord): void {
    this.#identities.set(identity.agentIdentityId, cloneIdentity(identity));
  }

  findByAgentDid(agentDid: string): PlatformIdentityRecord | undefined {
    for (const identity of this.#identities.values()) {
      if (identity.agentDid === agentDid) {
        return cloneIdentity(identity);
      }
    }

    return undefined;
  }

  findByServiceDid(serviceDid: string): PlatformIdentityRecord | undefined {
    for (const identity of this.#identities.values()) {
      if (identity.serviceDid === serviceDid) {
        return cloneIdentity(identity);
      }
    }

    return undefined;
  }

  findByAgentDidId(agentDidId: string | undefined): PlatformIdentityRecord | undefined {
    if (agentDidId === undefined) {
      return undefined;
    }

    for (const identity of this.#identities.values()) {
      if (identity.agentDidId === agentDidId) {
        return cloneIdentity(identity);
      }
    }

    return undefined;
  }

  get(agentIdentityId: string): PlatformIdentityRecord | undefined {
    const identity = this.#identities.get(agentIdentityId);

    return identity === undefined ? undefined : cloneIdentity(identity);
  }

  list(query: PlatformIdentityListQuery = {}): PlatformIdentityListResult {
    const identities = [...this.#identities.values()]
      .filter(
        (identity) => query.serviceDid === undefined || identity.serviceDid === query.serviceDid
      )
      .filter((identity) => query.status === undefined || identity.status === query.status)
      .sort((left, right) => {
        const created = left.createdAt.localeCompare(right.createdAt);
        const ordered =
          created === 0 ? left.agentIdentityId.localeCompare(right.agentIdentityId) : created;
        return query.descending === true ? -ordered : ordered;
      });
    const offset = query.offset ?? 0;
    const limit = query.limit ?? identities.length;

    return {
      identities: identities.slice(offset, offset + limit).map(cloneIdentity),
      total: identities.length
    };
  }

  update(
    agentIdentityId: string,
    update: { status: PlatformIdentityRecord["status"]; updatedAt: string }
  ): PlatformIdentityRecord | undefined {
    const identity = this.#identities.get(agentIdentityId);

    if (identity === undefined) {
      return undefined;
    }

    const updated = {
      ...identity,
      status: update.status,
      updatedAt: update.updatedAt
    };

    this.#identities.set(agentIdentityId, updated);
    return cloneIdentity(updated);
  }
}

class ExampleIdempotencyStore implements PlatformIdempotencyStore {
  readonly #records = new Map<string, PlatformIdempotencyRecord>();

  get(principal: string, idempotencyKey: string): PlatformIdempotencyRecord | undefined {
    const record = this.#records.get(`${principal}\u001f${idempotencyKey}`);

    return record === undefined ? undefined : structuredClone(record);
  }

  set(record: PlatformIdempotencyRecord): void {
    this.#records.set(`${record.principal}\u001f${record.idempotencyKey}`, structuredClone(record));
  }
}

class ExampleReplayStore implements PlatformReplayStore {
  readonly #seen = new Map<string, number>();

  consume(key: string, expiresAt: Date): boolean {
    const now = Date.now();

    for (const [seenKey, expires] of this.#seen) {
      if (expires <= now) {
        this.#seen.delete(seenKey);
      }
    }

    if (this.#seen.has(key)) {
      return false;
    }

    this.#seen.set(key, expiresAt.getTime());
    return true;
  }
}

class ExampleKeyStore implements PlatformKeyStore {
  readonly #keys = new Map<
    string,
    {
      privateKey: KeyObject;
      publicKey: KeyObject;
      publicKeyJwk: Record<string, unknown>;
    }
  >();

  create(identity: PlatformIdentityRecord): void {
    this.#keys.set(identity.agentIdentityId, createExampleKeyMaterial(identity.agentDid));
  }

  didVerificationMethod(
    identity: PlatformIdentityRecord
  ): ManagedAgentDidVerificationMethodOptions {
    return {
      id: identity.keyId,
      publicKeyJwk: this.#key(identity).publicKeyJwk,
      relationships: ["authentication", "assertionMethod"],
      type: "JsonWebKey2020"
    };
  }

  sign(identity: PlatformIdentityRecord, claims: Parameters<PlatformKeyStore["sign"]>[1]) {
    return createJwtPlatformDelegatedSigner({
      alg: "ES256",
      allowInsecureLoopback: true,
      key: this.#key(identity).privateKey,
      kid: identity.keyId
    })(claims, {
      identity: createManagedAgentIdentity({
        agentDid: identity.agentDid,
        status: identity.status
      }),
      signingAlgorithms: identity.signingAlgorithms
    });
  }

  verificationKey(identity: PlatformIdentityRecord): KeyObject {
    return this.#key(identity).publicKey;
  }

  #key(identity: PlatformIdentityRecord) {
    const key = this.#keys.get(identity.agentIdentityId);

    if (key === undefined) {
      throw new Error(`No key material for ${identity.agentIdentityId}.`);
    }

    return key;
  }
}

const identityStore = new ExampleIdentityStore();
const keyStore = new ExampleKeyStore();
const platformKey = createExampleKeyMaterial(platformDid);
const platform = createAepPlatform({
  authorizer: {
    authorize: (_request, context) => isAuthorized(context)
  },
  didHost,
  didUrlTemplate,
  discovery: {
    endpointBase: "/v1/aep",
    endpoints: {
      hostedVerification: "/v1/aep/verifications",
      lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
      list: "/v1/aep/agent-identities",
      provision: "/v1/aep/agent-identities",
      sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
    },
    hostedVerification: true,
    platformDid,
    platformName: "Ephemeral AEP Platform"
  },
  idGenerator: randomUUID,
  idempotencyStore: new ExampleIdempotencyStore(),
  identityStore,
  keyStore,
  replayStore: new ExampleReplayStore(),
  serviceDidResolver: {
    async resolve(candidate) {
      if (!candidate.startsWith("did:web:")) {
        return false;
      }

      const response = await fetch(didWebDocumentUrl(candidate, { allowInsecureLoopback: true }), {
        headers: {
          Accept: "application/json"
        }
      });

      if (!response.ok) {
        return false;
      }

      const document: unknown = await response.json();

      return typeof document === "object" && document !== null && "id" in document
        ? document.id === candidate
        : false;
    }
  },
  signingAlgorithms: ["ES256"]
});

const app = express();
app.use(express.json({ type: ["application/json", AEP_MEDIA_TYPE] }));

app.get("/health", (_request, response) => {
  response.json({ ok: true });
});
app.get("/.well-known/aep-platform", (_request, response) => {
  sendPlatform(response, platform.discovery());
});
app.get("/.well-known/did.json", (_request, response) => {
  response.json(
    createExampleDidDocument(platformDid, platformKey.publicKeyJwk, [
      "authentication",
      "assertionMethod"
    ])
  );
});
app.get("/services/example-service/did.json", (_request, response) => {
  response.json(
    createExampleDidDocument(serviceDid, platformKey.publicKeyJwk, [
      "authentication",
      "assertionMethod"
    ])
  );
});
app.get("/agents/:agentDidId/did.json", (request, response, next) => {
  try {
    const identity = identityStore.findByAgentDidId(request.params.agentDidId);

    if (identity === undefined) {
      response.status(404).json({ error: "not_found" });
      return;
    }

    response.json(
      createManagedAgentDidDocument({
        identity: createManagedAgentIdentity({
          agentDid: identity.agentDid,
          status: identity.status
        }),
        verificationMethods: [keyStore.didVerificationMethod(identity)]
      })
    );
  } catch (error) {
    next(error);
  }
});

app.get("/v1/aep/agent-identities", async (request, response, next) => {
  try {
    sendPlatform(response, await platform.list(listQueryFrom(request), contextFrom(request)));
  } catch (error) {
    next(error);
  }
});
app.post("/v1/aep/agent-identities", async (request, response, next) => {
  try {
    const result = await platform.provision(request.body as unknown, contextFrom(request));
    logProvision(result);
    sendPlatform(response, result);
  } catch (error) {
    next(error);
  }
});
app.get("/v1/aep/agent-identities/:agentIdentityId", async (request, response, next) => {
  try {
    sendPlatform(
      response,
      await platform.getIdentity(request.params.agentIdentityId, contextFrom(request))
    );
  } catch (error) {
    next(error);
  }
});
app.patch("/v1/aep/agent-identities/:agentIdentityId", async (request, response, next) => {
  try {
    sendPlatform(
      response,
      await platform.updateIdentity(
        request.params.agentIdentityId,
        request.body as unknown,
        contextFrom(request)
      )
    );
  } catch (error) {
    next(error);
  }
});
app.post("/v1/aep/agent-identities/:agentIdentityId/sign", async (request, response, next) => {
  try {
    const result = await platform.sign(
      request.params.agentIdentityId,
      request.body as unknown,
      contextFrom(request)
    );
    logSign(request.params.agentIdentityId, result);
    sendPlatform(response, result);
  } catch (error) {
    next(error);
  }
});
app.post("/v1/aep/verifications", async (request, response, next) => {
  try {
    const result = await platform.verify(request.body as unknown, contextFrom(request));
    logVerification(result);
    sendPlatform(response, result);
  } catch (error) {
    next(error);
  }
});

app.use(
  (error: unknown, _request: Request, response: Response, _next: (error?: unknown) => void) => {
    response.status(500).json({
      error: "internal_error",
      message: error instanceof Error ? error.message : "Unknown error"
    });
  }
);

app.listen(port, host, () => {
  console.log(`AEP ephemeral platform listening on ${publicBaseUrl}`);
  console.log(`Platform DID: ${platformDid}`);
});

function createExampleKeyMaterial(_did: string): {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyJwk: Record<string, unknown>;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });

  return {
    privateKey,
    publicKey,
    publicKeyJwk: recordFromUnknown(publicKey.export({ format: "jwk" }))
  };
}

function createExampleDidDocument(
  did: string,
  publicKeyJwk: Record<string, unknown>,
  relationships: NonNullable<ManagedAgentDidVerificationMethodOptions["relationships"]>
): DidDocument {
  return createManagedAgentDidDocument({
    identity: createManagedAgentIdentity({ agentDid: did }),
    verificationMethods: [
      {
        id: did,
        publicKeyJwk,
        relationships,
        type: "JsonWebKey2020"
      }
    ]
  });
}

function contextFrom(request: Request): PlatformRequestContext {
  const authorization = request.header("authorization");
  const idempotencyKey = request.header("idempotency-key");

  return {
    ...(authorization === undefined ? {} : { authorization }),
    ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
    ...(authorization === undefined ? {} : { subject: "demo-owner" })
  };
}

function isAuthorized(context: PlatformRequestContext): boolean {
  return context.authorization === demoAuthorization;
}

function listQueryFrom(request: Request): PlatformIdentityListQuery {
  const limit = numberQuery(request.query["limit"]);
  const offset = numberQuery(request.query["offset"]);
  const serviceDid = stringQuery(request.query["service_did"]);
  const status = stringQuery(request.query["status"]);

  return {
    ...(limit === undefined ? {} : { limit }),
    ...(offset === undefined ? {} : { offset }),
    ...(serviceDid === undefined ? {} : { serviceDid }),
    ...(status === undefined ? {} : { status: statusFromQuery(status) })
  };
}

function statusFromQuery(status: string): PlatformIdentityRecord["status"] {
  if (
    status !== "active" &&
    status !== "revoked" &&
    status !== "suspended" &&
    status !== "terminated"
  ) {
    throw new TypeError(`Unsupported status query: ${status}`);
  }

  return status;
}

function stringQuery(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberQuery(value: unknown): number | undefined {
  if (typeof value !== "string" || value.length === 0) {
    return undefined;
  }

  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new TypeError(`Invalid numeric query: ${value}`);
  }

  return parsed;
}

function sendPlatform<TBody>(response: Response, result: PlatformHttpResponse<TBody>): void {
  response.type(result.contentType).status(result.status).json(result.body);
}

function logProvision(result: PlatformHttpResponse<unknown>): void {
  if (!isPlatformAgentIdentity(result.body)) {
    logPlatformProblem("Provision Agent identity", result);
    return;
  }

  console.log(
    [
      "Provisioned Agent identity",
      `status=${result.status}`,
      `agent_identity_id=${result.body.agent_identity_id}`,
      `agent_did=${result.body.agent_did}`,
      `service_did=${result.body.service_did}`,
      `state=${result.body.status}`
    ].join(" ")
  );
}

function logSign(agentIdentityId: string | undefined, result: PlatformHttpResponse<unknown>): void {
  if (!isPlatformSignResponse(result.body) || result.body.status !== "completed") {
    logPlatformProblem("Sign client assertion", result);
    return;
  }

  console.log(
    [
      "Signed client assertion",
      `status=${result.status}`,
      `agent_identity_id=${agentIdentityId ?? "unknown"}`,
      `agent_did=${result.body.agent_did}`,
      `service_did=${result.body.service_did}`,
      `jti=${result.body.jti}`
    ].join(" ")
  );
}

function logVerification(result: PlatformHttpResponse<unknown>): void {
  if (!isPlatformVerificationResponse(result.body)) {
    logPlatformProblem("Verify client assertion", result);
    return;
  }

  console.log(
    [
      "Verified client assertion",
      `status=${result.status}`,
      `verified=${String(result.body.verified)}`,
      `reason=${result.body.reason}`,
      `op=${result.body.op ?? "unknown"}`,
      `agent_identity_id=${result.body.agent_identity_id ?? "unknown"}`,
      `agent_did=${result.body.agent_did ?? "unknown"}`,
      `service_did=${result.body.service_did}`
    ].join(" ")
  );
}

function logPlatformProblem(operation: string, result: PlatformHttpResponse<unknown>): void {
  console.log(`${operation} failed status=${result.status}`);
}

function isPlatformAgentIdentity(value: unknown): value is PlatformAgentIdentity {
  return (
    isRecord(value) &&
    typeof value["agent_identity_id"] === "string" &&
    typeof value["agent_did"] === "string" &&
    typeof value["service_did"] === "string" &&
    typeof value["status"] === "string"
  );
}

function isPlatformSignResponse(value: unknown): value is PlatformSignResponse {
  return (
    isRecord(value) &&
    typeof value["agent_did"] === "string" &&
    typeof value["service_did"] === "string" &&
    typeof value["jti"] === "string"
  );
}

function isPlatformVerificationResponse(value: unknown): value is PlatformVerificationResponse {
  return (
    isRecord(value) &&
    typeof value["verified"] === "boolean" &&
    typeof value["reason"] === "string" &&
    typeof value["service_did"] === "string"
  );
}

function cloneIdentity(identity: PlatformIdentityRecord): PlatformIdentityRecord {
  return {
    ...identity,
    signingAlgorithms: [...identity.signingAlgorithms]
  };
}

function recordFromUnknown(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Expected a JSON object.");
  }

  return value as Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
