#!/usr/bin/env node

import { generateKeyPairSync } from "node:crypto";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";

import {
  createAepPlatform,
  createJwtPlatformDelegatedSigner,
  createPlatformDiscoveryDocument,
  createPlatformLifecycleRequest
} from "../packages/platform/dist/index.js";

const NOW = new Date("2026-07-06T12:00:00.000Z");
const PRINCIPAL = "stable-principal-123";
const SERVICE_DID = "did:web:api.service.example";

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });

for await (const line of input) {
  if (line.trim() === "") continue;
  const request = JSON.parse(line);
  const result = await evaluate(request);
  process.stdout.write(
    JSON.stringify({ protocol_version: "1", sequence: request.sequence, ...result }) + "\n"
  );
}

async function evaluate(request) {
  try {
    const passed = await evaluateCase(request.vector.id, request.case);
    return passed
      ? { status: "passed" }
      : { status: "failed", message: "Public Platform API result did not match the vector" };
  } catch (error) {
    return {
      status: "failed",
      message: error instanceof Error ? error.message.slice(0, 1024) : "Platform evaluation failed"
    };
  }
}

async function evaluateCase(id, testCase) {
  switch (id) {
    case "authorization-required":
      return evaluateAuthorizationRequired(testCase);
    case "discovery":
      return evaluateDiscovery(testCase);
    case "idempotency-replay-conflict":
      return evaluateIdempotency(testCase);
    case "lifecycle-request":
      return isDeepStrictEqual(
        createPlatformLifecycleRequest({ status: testCase.input.status }),
        testCase.input
      );
    case "lifecycle-response":
      return evaluateLifecycleResponse(testCase);
    case "provision-response":
      return evaluateProvisionResponse(testCase);
    case "list-response":
      return evaluateListResponse(testCase);
    case "provision-request":
      return evaluateProvisionRequest(testCase);
    case "provision-response-distinct-services":
      return evaluateDistinctServices(testCase);
    case "sign-request":
      return evaluateSignRequest(testCase);
    case "sign-response-pending":
      return evaluatePendingSign(testCase);
    case "sign-response":
      return evaluateCompletedSign(testCase);
    case "verification-authenticate-missing-resource":
      return evaluateMissingResource(testCase);
    case "verification-request":
      return evaluateVerificationRequest(testCase);
    case "verification-response-recognized":
    case "verification-response-unrecognized":
      return evaluateVerificationResponse(testCase);
    default:
      throw new Error("No Platform operation maps vector " + id);
  }
}

async function evaluateAuthorizationRequired(testCase) {
  let missingAuthorizerRejected = false;
  try {
    platformFixture({ authorizer: undefined });
  } catch {
    missingAuthorizerRejected = true;
  }

  const operations = [];
  let allowed = true;
  const identityStore = createMemoryIdentityStore();
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keyStore = createMemoryKeyStore({
    sign(identity, claims) {
      return createJwtPlatformDelegatedSigner({
        alg: "ES256",
        key: privateKey,
        kid: identity.keyId
      })(claims, {
        identity: {
          agentDid: identity.agentDid,
          createdAt: identity.createdAt,
          status: identity.status,
          updatedAt: identity.updatedAt
        },
        signingAlgorithms: identity.signingAlgorithms
      });
    },
    verificationKey: () => publicKey
  });
  const platform = platformFixture({
    authorizer: {
      authorize(request) {
        operations.push(request.operation);
        return allowed;
      }
    },
    identityStore,
    keyStore
  });
  const provision = await platform.provision(
    { service_did: SERVICE_DID },
    { idempotencyKey: "authorization-setup", subject: PRINCIPAL }
  );
  const identityId = provision.body.agent_identity_id;
  const sign = await platform.sign(identityId, signRequest(), {
    idempotencyKey: "authorization-sign-setup",
    now: NOW,
    subject: PRINCIPAL
  });
  operations.length = 0;
  allowed = false;

  const didDocument = await platform.getDidDocument(identityId);
  const identity = await platform.getIdentity(identityId);
  const list = await platform.list();
  const deniedProvision = await platform.provision(
    { service_did: "did:web:denied.service.example" },
    { idempotencyKey: "authorization-provision-denied", subject: PRINCIPAL }
  );
  const deniedSign = await platform.sign(identityId, signRequest(), {
    idempotencyKey: "authorization-sign-denied",
    subject: PRINCIPAL
  });
  const deniedUpdate = await platform.updateIdentity(identityId, { status: "suspended" });
  const deniedVerification = await platform.verify(
    {
      client_assertion: sign.body.client_assertion,
      op: "enroll",
      service_did: SERVICE_DID
    },
    { idempotencyKey: "authorization-verify-denied", now: NOW, subject: PRINCIPAL }
  );
  const stored = await identityStore.list({});
  const managementResponses = [identity, list, deniedProvision, deniedSign, deniedUpdate];

  return (
    missingAuthorizerRejected === (testCase.expected.missing_authorizer === "construction-error") &&
    (didDocument.status === 200) === testCase.expected.did_document_public &&
    managementResponses.every(
      (response) =>
        response.status === testCase.expected.management_denied_status &&
        response.body.code === testCase.expected.management_denied_code
    ) &&
    deniedVerification.body.verified === testCase.expected.verification_denied.verified &&
    deniedVerification.body.reason === testCase.expected.verification_denied.reason &&
    (stored.identities.length === 1) === !testCase.expected.side_effects &&
    isDeepStrictEqual([...new Set(operations)].sort(), [...testCase.input.private_operations].sort())
  );
}

function evaluateDiscovery(testCase) {
  const document = createPlatformDiscoveryDocument({
    didUrlTemplate: testCase.expected.identity.did_url_template,
    endpointBase: testCase.expected.http.endpoint_base,
    endpoints: {
      hostedVerification: testCase.expected.endpoints.hosted_verification,
      lifecycle: testCase.expected.endpoints.lifecycle,
      list: testCase.expected.endpoints.list,
      provision: testCase.expected.endpoints.provision,
      sign: testCase.expected.endpoints.sign
    },
    hostedVerification: testCase.expected.platform.hosted_verification,
    platformDid: testCase.expected.platform.did,
    platformName: testCase.expected.platform.name,
    signingAlgorithms: testCase.expected.signing.algorithms
  });
  return isDeepStrictEqual(document, testCase.expected);
}

async function evaluateIdempotency(testCase) {
  const platform = platformFixture();
  const context = {
    idempotencyKey: "01J0AEPPLATFORM000000000001",
    subject: testCase.input.principal
  };
  const provision = await platform.provision({ service_did: SERVICE_DID }, context);
  const replay = await platform.provision({ service_did: SERVICE_DID }, context);
  const conflict = await platform.provision(
    { service_did: "did:web:billing.service.example" },
    context
  );
  if (
    !isDeepStrictEqual(replay, provision) ||
    conflict.status !== testCase.expected.changed_input_or_operation_status ||
    conflict.body.code !== testCase.expected.changed_input_or_operation_code
  ) {
    return false;
  }

  const identityId = provision.body.agent_identity_id;
  const signContext = { idempotencyKey: testCase.input.initial_sign_key, subject: PRINCIPAL };
  const sign = await platform.sign(identityId, signRequest(), signContext);
  const signReplay = await platform.sign(identityId, signRequest(), signContext);
  const signConflict = await platform.sign(
    identityId,
    { ...signRequest(), jti: "changed" },
    signContext
  );
  if (
    !isDeepStrictEqual(signReplay, sign) ||
    signConflict.status !== 409 ||
    signConflict.body.code !== "idempotency_conflict"
  ) {
    return false;
  }

  const verificationContext = {
    idempotencyKey: testCase.input.final_sign_key,
    subject: PRINCIPAL
  };
  const verification = {
    client_assertion: "header.payload.signature",
    op: "enroll",
    service_did: SERVICE_DID
  };
  const verified = await platform.verify(verification, verificationContext);
  const verifiedReplay = await platform.verify(verification, verificationContext);
  const verificationConflict = await platform.verify(
    { ...verification, op: "status" },
    verificationContext
  );
  return (
    isDeepStrictEqual(verifiedReplay, verified) &&
    verificationConflict.status === 409 &&
    verificationConflict.body.code === "idempotency_conflict" &&
    Number(testCase.expected.retention_seconds_minimum) === 3600
  );
}

async function evaluateProvisionRequest(testCase) {
  let resolvedServiceDid;
  const response = await platformFixture({
    serviceDidResolver: {
      resolve(serviceDid) {
        resolvedServiceDid = serviceDid;
        return true;
      }
    }
  }).provision(testCase.input, {
    idempotencyKey: testCase.expected.idempotency_key_header,
    subject: PRINCIPAL
  });
  return response.status === 200 && resolvedServiceDid === testCase.input.service_did;
}

async function evaluateProvisionResponse(testCase) {
  const expected = testCase.expected;
  const platform = platformFixture({
    agentDidIdGenerator: () => expected.agent_did.split(":").at(-1),
    clock: () => new Date(expected.created_at),
    idGenerator: () => expected.agent_identity_id.replace(/^pai_/, "")
  });
  const response = await platform.provision(
    { service_did: expected.service_did },
    { idempotencyKey: "provision-response", subject: PRINCIPAL }
  );
  return (
    response.status === 200 && isDeepStrictEqual(normalizeIdentityDates(response.body), expected)
  );
}

async function evaluateListResponse(testCase) {
  const expectedIdentity = identityRecord(testCase.expected.data[0]);
  const otherIdentity = {
    ...expectedIdentity,
    agentDid: "did:web:p.example:a:other",
    agentDidId: "other",
    agentIdentityId: "pai_other",
    serviceDid: "did:web:other.service.example"
  };
  const platform = platformFixture({
    identityStore: createMemoryIdentityStore([otherIdentity, expectedIdentity])
  });
  const query = testCase.input.query;
  const response = await platform.list({
    descending: query.descending,
    limit: query.limit,
    offset: query.offset,
    serviceDid: query.service_did,
    status: query.status
  });
  return (
    response.status === 200 &&
    isDeepStrictEqual(normalizeListDates(response.body), testCase.expected)
  );
}

async function evaluateDistinctServices(testCase) {
  const identityIds = [
    testCase.expected.first_response.agent_identity_id.replace(/^pai_/, ""),
    testCase.expected.second_response.agent_identity_id.replace(/^pai_/, "")
  ];
  const agentDidIds = [
    testCase.expected.first_response.agent_did.split(":").at(-1),
    testCase.expected.second_response.agent_did.split(":").at(-1)
  ];
  const clockValues = [
    testCase.expected.first_response.created_at,
    testCase.expected.second_response.created_at
  ];
  let currentTime = clockValues[0];
  const platform = platformFixture({
    agentDidIdGenerator: () => agentDidIds.shift(),
    clock: () => new Date(currentTime),
    idGenerator: () => identityIds.shift()
  });
  const firstResponse = await platform.provision(
    { service_did: testCase.input.first_request.service_did },
    { idempotencyKey: testCase.input.first_request.idempotency_key_header, subject: PRINCIPAL }
  );
  currentTime = clockValues[1];
  const secondResponse = await platform.provision(
    { service_did: testCase.input.second_request.service_did },
    { idempotencyKey: testCase.input.second_request.idempotency_key_header, subject: PRINCIPAL }
  );
  const first = normalizeIdentityDates(firstResponse.body);
  const second = normalizeIdentityDates(secondResponse.body);
  return (
    firstResponse.status === 200 &&
    secondResponse.status === 200 &&
    isDeepStrictEqual(first, testCase.expected.first_response) &&
    isDeepStrictEqual(second, testCase.expected.second_response) &&
    first.agent_did !== second.agent_did &&
    first.service_did === testCase.input.first_request.service_did &&
    second.service_did === testCase.input.second_request.service_did
  );
}

async function evaluateLifecycleResponse(testCase) {
  const expected = testCase.expected;
  const identityStore = createMemoryIdentityStore([
    {
      agentDid: expected.agent_did,
      agentDidId: expected.agent_did.split(":").at(-1),
      agentIdentityId: expected.agent_identity_id,
      createdAt: expected.created_at,
      didDocumentUrl: expected.did_document_url,
      keyId: expected.key_id,
      serviceDid: expected.service_did,
      signingAlgorithms: expected.signing_algorithms,
      status: "active",
      updatedAt: expected.created_at
    }
  ]);
  const response = await platformFixture({
    clock: () => new Date(expected.updated_at),
    identityStore
  }).updateIdentity(expected.agent_identity_id, { status: expected.status });
  return (
    response.status === 200 && isDeepStrictEqual(normalizeIdentityDates(response.body), expected)
  );
}

async function evaluateSignRequest(testCase) {
  let observed;
  const identity = defaultIdentityRecord(testCase.input.service_did);
  const response = await platformFixture({
    identityStore: createMemoryIdentityStore([identity]),
    keyStore: createMemoryKeyStore({
      sign(_identity, claims, context) {
        observed = { claims, context };
        return "header.payload.signature";
      }
    })
  }).sign(identity.agentIdentityId, testCase.input, {
    idempotencyKey: testCase.expected.idempotency_key_header,
    subject: PRINCIPAL
  });
  return (
    response.status === 200 &&
    observed?.context.idempotencyKey === testCase.expected.idempotency_key_header &&
    observed?.claims.aud === testCase.input.service_did &&
    observed?.claims.jti === testCase.input.jti &&
    observed?.claims.op === testCase.input.op
  );
}

async function evaluatePendingSign(testCase) {
  const identity = defaultIdentityRecord();
  const response = await platformFixture({
    identityStore: createMemoryIdentityStore([identity]),
    signHandler() {
      return {
        body: testCase.expected,
        contentType: "application/aep+json",
        status: 202
      };
    }
  }).sign(identity.agentIdentityId, signRequest(), {
    idempotencyKey: testCase.input.idempotency_key_header,
    subject: PRINCIPAL
  });
  return response.status === 202 && isDeepStrictEqual(response.body, testCase.expected);
}

async function evaluateCompletedSign(testCase) {
  const expected = testCase.expected;
  const identity = defaultIdentityRecord(expected.service_did, { ...expected, status: "active" });
  const response = await platformFixture({
    clock: () => new Date(expected.issued_at),
    identityStore: createMemoryIdentityStore([identity]),
    keyStore: createMemoryKeyStore({ sign: () => expected.client_assertion })
  }).sign(
    identity.agentIdentityId,
    {
      jti: expected.jti,
      lifetime_seconds: String(
        (Date.parse(expected.expires_at) - Date.parse(expected.issued_at)) / 1000
      ),
      op: "enroll",
      platform_context: expected.platform_context,
      service_did: expected.service_did
    },
    { idempotencyKey: "sign-response", subject: PRINCIPAL }
  );
  if (response.status !== 200) {
    throw new Error(`Sign returned ${response.status}: ${JSON.stringify(response.body)}`);
  }
  assertMatch(normalizeDates(response.body), testCase.expected);
  return true;
}

async function evaluateMissingResource(testCase) {
  let rejected = false;
  try {
    await platformFixture().verify(testCase.input.request, {
      idempotencyKey: "verification-missing-resource",
      subject: PRINCIPAL
    });
  } catch {
    rejected = true;
  }
  return rejected === !testCase.expected.valid;
}

async function evaluateVerificationRequest(testCase) {
  const response = await platformFixture().verify(testCase.input, {
    idempotencyKey: testCase.expected.idempotency_key_header,
    subject: PRINCIPAL
  });
  return response.status === 200;
}

async function evaluateVerificationResponse(testCase) {
  const expected = testCase.expected;
  const identity = defaultIdentityRecord(expected.service_did, expected);
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keyStore = createMemoryKeyStore({
    sign(managedIdentity, claims) {
      return createJwtPlatformDelegatedSigner({
        alg: "ES256",
        key: privateKey,
        kid: managedIdentity.keyId
      })(claims, {
        identity: {
          agentDid: managedIdentity.agentDid,
          createdAt: managedIdentity.createdAt,
          status: managedIdentity.status,
          updatedAt: managedIdentity.updatedAt
        },
        signingAlgorithms: managedIdentity.signingAlgorithms
      });
    },
    verificationKey: () => publicKey
  });
  const platform = platformFixture({
    identityStore: createMemoryIdentityStore([identity]),
    keyStore
  });
  let clientAssertion = "not-a-jwt";
  if (expected.verified === true) {
    const signed = await platform.sign(identity.agentIdentityId, signRequest(), {
      idempotencyKey: "verification-sign",
      now: NOW,
      subject: PRINCIPAL
    });
    clientAssertion = signed.body.client_assertion;
  }
  const response = await platform.verify(
    { client_assertion: clientAssertion, op: "enroll", service_did: expected.service_did },
    { idempotencyKey: "verification-response", now: NOW, subject: PRINCIPAL }
  );
  return response.status === 200 && isDeepStrictEqual(response.body, expected);
}

function platformFixture(options = {}) {
  return createAepPlatform({
    agentDidIdGenerator: options.agentDidIdGenerator,
    authorizer: "authorizer" in options ? options.authorizer : { authorize: () => true },
    clock: options.clock ?? (() => NOW),
    didHost: "p.example",
    didPathPrefix: "a",
    didUrlTemplate: "https://p.example/a/{agent_did_id}/did.json",
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
      platformDid: "did:web:p.example",
      platformName: "Example Platform"
    },
    idGenerator: options.idGenerator ?? (() => "01J0AEPPLATFORM000000000001"),
    idempotencyStore: createMemoryIdempotencyStore(),
    identityStore: options.identityStore ?? createMemoryIdentityStore(),
    keyStore: options.keyStore ?? createMemoryKeyStore(),
    replayStore: createMemoryReplayStore(),
    serviceDidResolver: options.serviceDidResolver ?? { resolve: () => true },
    signHandler: options.signHandler,
    signingAlgorithms: ["ES256"]
  });
}

function createMemoryKeyStore(overrides = {}) {
  return {
    create() {},
    didVerificationMethod(identity) {
      return { id: identity.keyId, publicKeyPem: "public-key", type: "JsonWebKey2020" };
    },
    sign() {
      return "header.payload.signature";
    },
    verificationKey() {
      return "public-key";
    },
    ...overrides
  };
}

function createMemoryIdentityStore(initial = []) {
  const identities = new Map(
    initial.map((identity) => [identity.agentIdentityId, structuredClone(identity)])
  );
  return {
    create(identity) {
      identities.set(identity.agentIdentityId, structuredClone(identity));
    },
    findByAgentDid(agentDid) {
      return structuredClone([...identities.values()].find((value) => value.agentDid === agentDid));
    },
    findByServiceDid(serviceDid) {
      return structuredClone(
        [...identities.values()].find((value) => value.serviceDid === serviceDid)
      );
    },
    get(agentIdentityId) {
      return structuredClone(identities.get(agentIdentityId));
    },
    list(query) {
      const values = [...identities.values()]
        .filter(
          (identity) =>
            (query.serviceDid === undefined || identity.serviceDid === query.serviceDid) &&
            (query.status === undefined || identity.status === query.status)
        )
        .sort((left, right) => {
          const created = left.createdAt.localeCompare(right.createdAt);
          const ordered =
            created === 0 ? left.agentIdentityId.localeCompare(right.agentIdentityId) : created;
          return query.descending === true ? -ordered : ordered;
        });
      return {
        identities: values.slice(
          query.offset ?? 0,
          (query.offset ?? 0) + (query.limit ?? values.length)
        ),
        total: values.length
      };
    },
    update(agentIdentityId, update) {
      const identity = identities.get(agentIdentityId);
      if (identity === undefined) return undefined;
      const updated = { ...identity, ...update };
      identities.set(agentIdentityId, updated);
      return structuredClone(updated);
    }
  };
}

function createMemoryIdempotencyStore() {
  const records = new Map();
  return {
    get(principal, idempotencyKey) {
      return structuredClone(records.get(`${principal}\u001f${idempotencyKey}`));
    },
    set(record) {
      records.set(`${record.principal}\u001f${record.idempotencyKey}`, structuredClone(record));
    }
  };
}

function createMemoryReplayStore() {
  const seen = new Set();
  return {
    consume(key) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }
  };
}

function signRequest() {
  return {
    jti: "01J0AEPASSERTION0000000001",
    lifetime_seconds: "300",
    op: "enroll",
    service_did: SERVICE_DID
  };
}

function defaultIdentityRecord(serviceDid = SERVICE_DID, values = {}) {
  const agentDid = values.agent_did ?? "did:web:p.example:a:4Yf7p2xQd9";
  return {
    agentDid,
    agentDidId: agentDid.split(":").at(-1),
    agentIdentityId: values.agent_identity_id ?? "pai_01J0AEPPLATFORM000000000001",
    createdAt: values.created_at ?? "2026-07-06T12:00:00Z",
    didDocumentUrl: values.did_document_url ?? "https://p.example/a/4Yf7p2xQd9/did.json",
    keyId: values.key_id ?? agentDid,
    serviceDid,
    signingAlgorithms: values.signing_algorithms ?? ["ES256"],
    status: values.status ?? "active",
    updatedAt: values.updated_at ?? "2026-07-06T12:00:00Z"
  };
}

function identityRecord(value) {
  return defaultIdentityRecord(value.service_did, value);
}

function normalizeDates(value) {
  return {
    ...value,
    expires_at: value.expires_at.replace(".000Z", "Z"),
    issued_at: value.issued_at.replace(".000Z", "Z")
  };
}

function normalizeIdentityDates(value) {
  return {
    ...value,
    created_at: value.created_at.replace(".000Z", "Z"),
    updated_at: value.updated_at.replace(".000Z", "Z")
  };
}

function normalizeListDates(value) {
  return {
    ...value,
    data: value.data.map(normalizeIdentityDates)
  };
}

function assertMatch(actual, expected) {
  if (!isDeepStrictEqual(actual, expected)) {
    throw new Error(`Actual ${JSON.stringify(actual)} did not match ${JSON.stringify(expected)}`);
  }
}
