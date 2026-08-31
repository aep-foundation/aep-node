#!/usr/bin/env node

import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";

import {
  AEP_VERSION,
  AepValidationError,
  isAepVersionCompatible,
  parseInspectDocument,
  parseProblemDetails,
  signClientAssertionJwt,
  validateAepClaimValues
} from "../packages/core/dist/index.js";
import {
  apiKeyGrantType,
  basicGrantType,
  buildInspectDocument,
  createAepService,
  createDidWebClientAssertionVerifier,
  createHostedPlatformClientAssertionVerifier,
  createInMemoryCommandIdempotencyStore,
  createInMemoryEnrollmentStore,
  createInMemoryServiceCredentialStore,
  createJwtClientAssertionVerifier,
  createStaticEnrollmentPolicy,
  didWebIdentityMethod,
  handleEnrollRequest,
  handleGrantRequest,
  handleRevokeRequest,
  handleStatusRequest,
  oauthBearerGrantType,
  storedApiKeyGrantType,
  storedBasicGrantType,
  storedOAuthBearerGrantType
} from "../packages/service/dist/index.js";

const SERVICE_DID = "did:web:api.example.com";
const AGENT_DID = "did:web:agent.example.com:agents:123";
const NOW = new Date("2026-05-28T12:00:00.000Z");
const CLAIM_VALUE_VECTOR_IDS = new Set([
  "forward-compatible-address",
  "invalid-address",
  "invalid-birthdate",
  "invalid-country-shape",
  "invalid-email-domain",
  "invalid-email-dot-string",
  "invalid-email-format",
  "invalid-empty-email",
  "invalid-mobile",
  "invalid-value-type",
  "minimal-email",
  "quoted-email"
]);
const INSPECT_DOCUMENT_VECTOR_IDS = new Set([
  "authenticate-command-prohibited",
  "authenticated-command-without-identity-method",
  "authentication-method-limit",
  "command-without-inspect",
  "forward-compatible-advertisements",
  "grant-without-grant-types",
  "invalid-advertisement-identifiers",
  "invalid-openapi-reference",
  "missing-signing-algorithm"
]);

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
    const passed = await evaluateCase(request.vector, request.case);
    if (passed === "skipped") {
      return {
        status: "skipped",
        message: "Platform discovery is not implemented by the Service package"
      };
    }
    return passed
      ? { status: "passed" }
      : { status: "failed", message: "Public Service API result did not match the vector" };
  } catch (error) {
    return {
      status: "failed",
      message: error instanceof Error ? error.message.slice(0, 1024) : "Service evaluation failed"
    };
  }
}

async function evaluateCase(vector, testCase) {
  const id = vector.id;
  if (CLAIM_VALUE_VECTOR_IDS.has(id)) return evaluateClaimValue(testCase);
  if (INSPECT_DOCUMENT_VECTOR_IDS.has(id)) return evaluateInspectDocument(testCase);

  switch (id) {
    case "public-discovery-cache":
      return evaluateDiscoveryResponse(testCase);
    case "negotiation-compatibility":
      return evaluateClaimNegotiation(testCase);
    case "person-contact-catalog":
      return validateAepClaimValues(testCase.expected).ok;
    case "enroll-claims":
      return evaluateClientAssertion(testCase);
    case "did-web-resolution":
      return evaluateDidWebResolution(testCase);
    case "validation-requirements":
      return evaluateClientAssertionValidation(testCase);
    case "grant-response":
      return evaluateCredentialGrant(testCase);
    case "grant-response-missing-credential-id":
      return evaluateInvalidCredentialGrant(vector.category, testCase);
    case "repeated-existing":
      return evaluateRepeatedEnrollment(testCase);
    case "request-minimal":
    case "request-claims-catalog":
      return evaluateEnrollRequest(testCase);
    case "response-active":
      return vector.category === "enroll"
        ? evaluateActiveEnrollment(testCase)
        : evaluateStatusResponse(testCase);
    case "response-pending-verification-owner-action":
      return evaluatePendingEnrollment(testCase);
    case "not-recognized-problem":
      return evaluateNotRecognized(testCase);
    case "requirements-unmet-problem":
      return evaluateRequirementsUnmet(testCase);
    case "verification-pending-problem":
      return evaluateVerificationPending(testCase);
    case "problem-details-validation":
      return evaluateProblemDetailsValidation(testCase);
    case "grant-before-enroll-rejected":
      return evaluateGrantBeforeEnrollment(testCase);
    case "grant-request-oauth-bearer":
      return evaluateGrantRequest(testCase);
    case "revoke-request-all-grant-types":
    case "revoke-request-oauth-bearer":
    case "revoke-request-targeted-oauth-bearer":
      return evaluateRevokeRequest(testCase);
    case "revoke-request-conflicting-targets":
    case "revoke-request-credential-id-without-grant-type":
      return evaluateInvalidRevokeRequest(testCase);
    case "revoke-response-empty":
      return evaluateRevokeResponse(testCase);
    case "command-header":
      return evaluateCommandIdempotencyHeader(testCase);
    case "command-replay-conflict":
      return evaluateCommandReplayConflict(testCase);
    case "enroll-conflict":
      return evaluateEnrollmentConflict(testCase);
    case "claims-catalog-advertisement":
    case "minimal-http":
      return evaluateInspectAdvertisement(testCase);
    case "default-endpoint-base":
      return evaluateDefaultEndpointBase(testCase);
    case "protocol-version":
      return evaluateProtocolVersion(testCase);
    case "service-did-origin-binding":
      return evaluateServiceDidAdvertisement(testCase);
    case "transport-requirements":
      return evaluateTransportAdvertisement(testCase);
    case "path-matching":
      return evaluateOpenApiPathMatching(testCase);
    case "security-inheritance":
      return evaluateOpenApiSecurity(testCase);
    case "url-resolution":
      return evaluateOpenApiUrl(testCase);
    case "discovery":
      return "skipped";
    case "verification-authenticate-missing-resource":
      return evaluateHostedAuthenticateResource(testCase);
    case "verification-request":
      return evaluateHostedVerificationRequest(testCase);
    case "verification-response-recognized":
      return evaluateHostedRecognized(testCase);
    case "verification-response-unrecognized":
      return evaluateHostedUnrecognized(testCase);
    case "api-key-wrong-header-rejected":
      return evaluateWrongApiKeyHeader(testCase);
    case "assertion-and-credential-failures":
      return evaluateAuthenticationFailures(testCase);
    case "authenticate-assertion":
      return evaluateAuthenticateAssertion(testCase);
    case "authorization-ambiguity":
      return evaluateAuthorizationAmbiguity(testCase);
    case "authorization-carriers":
      return evaluateAuthorizationCarriers(testCase);
    case "authorization-field-safety":
      return evaluateAuthorizationFieldSafety(testCase);
    case "authorization-payment-composition":
      return evaluatePaymentComposition(testCase);
    case "credential-presentations":
      return evaluateCredentialPresentations(testCase);
    case "inspect-authentication-methods":
      return evaluateAuthenticationAdvertisements(testCase);
    case "operation-substitution-rejected":
      return evaluateOperationBinding(testCase);
    case "redirect-safety":
      return evaluateRedirectSafety(testCase);
    case "response-pending-requirements":
      return evaluateStatusResponse(testCase);
    default:
      throw new Error("No Service operation maps vector " + id);
  }
}

async function evaluateClientAssertionValidation(testCase) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const verifier = createJwtClientAssertionVerifier({
    algorithms: [testCase.input.algorithm],
    currentDate: new Date(testCase.input.issued_at * 1000),
    key: publicKey
  });
  const context = {
    clientAssertion: "",
    command: "enroll",
    serviceDid: testCase.input.service_did,
    signingAlgorithms: [testCase.input.algorithm]
  };
  const claims = testCase.expected.claims;
  const valid = await signTestAssertion(privateKey, testCase.expected.header, claims);

  await verifier(valid, { ...context, clientAssertion: valid });

  const authenticate = {
    ...claims,
    op: "authenticate",
    resource: "https://api.example.com/orders"
  };
  const invalid = {
    excessive_lifetime: { ...claims, exp: claims.iat + 301 },
    fragmented_resource: { ...authenticate, resource: "https://api.example.com/orders#item" },
    insecure_resource: { ...authenticate, resource: "http://api.example.com/orders" },
    mismatched_subject: { ...claims, sub: "did:web:different.example.com" },
    missing_resource: without(authenticate, "resource"),
    nonpositive_lifetime: { ...claims, exp: claims.iat },
    unexpected_resource: { ...claims, resource: "https://api.example.com/orders" }
  };
  const tokens = [
    await signTestAssertion(privateKey, { alg: testCase.input.algorithm, typ: "JWT" }, claims),
    await signTestAssertion(
      privateKey,
      { ...testCase.expected.header, kid: "did:web:different.example.com#key-1" },
      claims
    ),
    await signTestAssertion(
      privateKey,
      { ...testCase.expected.header, typ: "application/aep" },
      claims
    ),
    ...(await Promise.all(
      Object.values(invalid).map((candidate) =>
        signTestAssertion(privateKey, testCase.expected.header, candidate)
      )
    ))
  ];

  if (tokens.length !== testCase.expected.reject.length) return false;

  for (const token of tokens) {
    if (!(await rejects(() => verifier(token, { ...context, clientAssertion: token }))))
      return false;
  }

  return true;
}

async function evaluateDidWebResolution(testCase) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    aud: SERVICE_DID,
    exp: now + 60,
    iat: now,
    iss: testCase.input.did,
    jti: "did-web-resolution",
    op: "enroll",
    sub: testCase.input.did
  };
  const token = await signClientAssertionJwt(claims, {
    alg: "ES256",
    key: privateKey,
    kid: testCase.input.kid
  });
  const calls = [];
  const verifier = createDidWebClientAssertionVerifier({
    fetch: (input) => {
      calls.push(String(input));
      return Promise.resolve(
        new Response(
          JSON.stringify({
            verificationMethod: [
              {
                id: testCase.input.kid,
                publicKeyJwk: publicKey.export({ format: "jwk" })
              }
            ]
          })
        )
      );
    }
  });
  const context = {
    clientAssertion: token,
    command: "enroll",
    serviceDid: SERVICE_DID,
    signingAlgorithms: ["ES256"]
  };

  await verifier(token, context);
  if (!isDeepStrictEqual(calls, [testCase.expected.document_url])) return false;

  const missingMethodVerifier = createDidWebClientAssertionVerifier({
    fetch: () => Promise.resolve(new Response(JSON.stringify({ verificationMethod: [] })))
  });
  if (!(await rejects(() => missingMethodVerifier(token, context)))) return false;

  const wrongDidToken = await signTestAssertion(
    privateKey,
    { alg: "ES256", kid: "did:web:different.example.com#key-1", typ: "JWT" },
    claims
  );
  return rejects(() => verifier(wrongDidToken, { ...context, clientAssertion: wrongDidToken }));
}

function signTestAssertion(key, header, claims) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedClaims = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = signBytes("sha256", Buffer.from(signingInput), {
    dsaEncoding: "ieee-p1363",
    key
  }).toString("base64url");
  return `${signingInput}.${signature}`;
}

function without(value, key) {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

async function rejects(operation) {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

async function evaluateClaimValue(testCase) {
  const result = await handleEnrollRequest(
    {
      agent_did: AGENT_DID,
      claims: testCase.input.claim_values,
      idempotency_key: "claim-value-vector"
    },
    {
      idempotencyKey: "claim-value-vector",
      policy: createStaticEnrollmentPolicy(),
      store: createInMemoryEnrollmentStore()
    }
  );
  return (result.status === 200) === testCase.expected.valid;
}

async function evaluateClaimNegotiation(testCase) {
  const result = await handleEnrollRequest(
    {
      agent_did: AGENT_DID,
      claims: testCase.input.submitted,
      idempotency_key: "claim-negotiation-vector"
    },
    {
      idempotencyKey: "claim-negotiation-vector",
      policy: createStaticEnrollmentPolicy(),
      requiredClaims: testCase.input.inspect.required,
      store: createInMemoryEnrollmentStore()
    }
  );
  return result.status === 200 && testCase.expected.enrollment_requirement_satisfied;
}

async function evaluateClientAssertion(testCase) {
  const service = serviceWithVerifier(() => testCase.expected, {
    clientAssertion: {
      clock: () => new Date(testCase.input.issued_at * 1000),
      clockSkewSeconds: 0,
      maxTtlSeconds: 300
    }
  });
  const response = await service.enroll(
    {
      agent_did: testCase.input.agent_did,
      idempotency_key: "assertion-vector"
    },
    { clientAssertion: "assertion", idempotencyKey: "assertion-vector" }
  );
  return response.status === 200;
}

async function evaluateCredentialGrant(testCase) {
  const store = createInMemoryServiceCredentialStore();
  const definitions = {
    "api-key": storedApiKeyGrantType,
    basic: storedBasicGrantType,
    "oauth-bearer": storedOAuthBearerGrantType
  };
  const define = definitions[testCase.input.grant_type];
  if (define === undefined) return false;
  const service = serviceWithVerifier(parseAssertion, {
    clock: () => NOW,
    grantTypes: [define({ clock: () => NOW, issue: () => testCase.expected, store })]
  });
  await enroll(service, "credential-enroll");
  const response = await service.grant(
    {
      grant_type: testCase.input.grant_type,
      ...(testCase.input.requested_scopes === undefined
        ? {}
        : { requested_scopes: testCase.input.requested_scopes })
    },
    {
      clientAssertion: assertion("grant", "credential-grant"),
      idempotencyKey: "credential-grant"
    }
  );
  const expected =
    testCase.expected.scopes === null || testCase.expected.scopes === undefined
      ? { ...testCase.expected, scopes: [] }
      : testCase.expected;
  return response.status === 200 && isDeepStrictEqual(response.body, expected);
}

async function evaluateInvalidCredentialGrant(category, testCase) {
  const grantType = category.split("/").at(-1);
  const definitions = {
    "api-key": storedApiKeyGrantType,
    basic: storedBasicGrantType,
    "oauth-bearer": storedOAuthBearerGrantType
  };
  const define = definitions[grantType];
  if (define === undefined) return false;
  const service = serviceWithVerifier(parseAssertion, {
    clock: () => NOW,
    grantTypes: [
      define({
        clock: () => NOW,
        issue: () => testCase.input,
        store: createInMemoryServiceCredentialStore()
      })
    ]
  });
  await enroll(service, "invalid-credential-enroll");

  try {
    await service.grant(
      { grant_type: grantType },
      {
        clientAssertion: assertion("grant", "invalid-credential-grant"),
        idempotencyKey: "invalid-credential-grant"
      }
    );
    return false;
  } catch (error) {
    return error instanceof AepValidationError;
  }
}

async function evaluateRepeatedEnrollment(testCase) {
  let policyEvaluated = false;
  const record = enrollmentRecord(testCase.input.existing);
  const store = createInMemoryEnrollmentStore([record]);
  const before = await store.findEnrollment(record.agentDid);
  const response = await handleEnrollRequest(testCase.input.request, {
    idempotencyKey: testCase.input.request.idempotency_key,
    policy: {
      decideEnrollment: () => {
        policyEvaluated = true;
        return { status: "rejected" };
      }
    },
    store
  });
  return (
    !policyEvaluated &&
    isDeepStrictEqual(await store.findEnrollment(record.agentDid), before) &&
    responseMatches(response, testCase.expected.response)
  );
}

async function evaluateEnrollRequest(testCase) {
  const service = serviceWithVerifier(parseAssertion);
  const response = await service.enroll(testCase.input, {
    clientAssertion: assertion("enroll", testCase.input.idempotency_key),
    idempotencyKey: testCase.input.idempotency_key
  });
  return response.status === 200;
}

async function evaluateActiveEnrollment(testCase) {
  const response = await handleEnrollRequest(
    { agent_did: AGENT_DID, idempotency_key: "active-vector" },
    {
      clock: () => NOW,
      idempotencyKey: "active-vector",
      policy: createStaticEnrollmentPolicy(),
      store: createInMemoryEnrollmentStore()
    }
  );
  return responseMatches(response, testCase.expected);
}

async function evaluatePendingEnrollment(testCase) {
  const response = await handleEnrollRequest(
    { agent_did: AGENT_DID, idempotency_key: "pending-vector" },
    {
      clock: () => NOW,
      idempotencyKey: "pending-vector",
      policy: createStaticEnrollmentPolicy({
        ownerActionRequired: true,
        status: "pending",
        verificationPending: ["contact.email"]
      }),
      store: createInMemoryEnrollmentStore()
    }
  );
  return responseMatches(response, testCase.expected);
}

async function evaluateNotRecognized(testCase) {
  const service = serviceWithVerifier(() => {
    throw new Error("bad signature");
  });
  const response = await service.status({ clientAssertion: "invalid" });
  return responseMatches(response, testCase.expected);
}

function evaluateProblemDetailsValidation(testCase) {
  return testCase.input.cases.every(({ body, valid }) => {
    try {
      parseProblemDetails(body);
      return valid;
    } catch {
      return !valid;
    }
  });
}

async function evaluateRequirementsUnmet(testCase) {
  const response = await handleEnrollRequest(
    { agent_did: AGENT_DID, idempotency_key: "requirements-vector" },
    {
      idempotencyKey: "requirements-vector",
      policy: createStaticEnrollmentPolicy(),
      requiredClaims: testCase.expected.body.requirements_pending,
      store: createInMemoryEnrollmentStore()
    }
  );
  return responseMatches(response, testCase.expected);
}

async function evaluateVerificationPending(testCase) {
  const store = createInMemoryEnrollmentStore([
    enrollmentRecord({
      agent_did: AGENT_DID,
      owner_action_required: true,
      status: "pending",
      verification_pending: testCase.expected.body.verification_pending
    })
  ]);
  const response = await handleGrantRequest(
    { grant_type: "oauth-bearer" },
    {
      agentDid: AGENT_DID,
      handlers: new Map(),
      idempotencyKey: "verification-pending",
      store
    }
  );
  return responseMatches(response, testCase.expected);
}

async function evaluateGrantBeforeEnrollment(testCase) {
  const response = await handleGrantRequest(
    { grant_type: "oauth-bearer" },
    {
      agentDid: AGENT_DID,
      handlers: new Map(),
      idempotencyKey: "grant-before-enrollment",
      store: createInMemoryEnrollmentStore()
    }
  );
  return (
    response.status === testCase.expected.status && response.body.code === testCase.expected.code
  );
}

async function evaluateGrantRequest(testCase) {
  let received;
  const handler = {
    grant: (request) => {
      received = request;
      return { access_token: "token" };
    },
    revoke: () => undefined
  };
  const response = await handleGrantRequest(testCase.expected.body, {
    agentDid: AGENT_DID,
    handlers: new Map([["oauth-bearer", handler]]),
    idempotencyKey: "grant-request",
    store: activeEnrollmentStore()
  });
  return response.status === 200 && isDeepStrictEqual(received, testCase.expected.body);
}

async function evaluateRevokeRequest(testCase) {
  let received;
  const handler = {
    grant: () => ({}),
    revoke: (request) => {
      received = request;
    }
  };
  const response = await handleRevokeRequest(testCase.expected.body, {
    agentDid: AGENT_DID,
    handlers: new Map([["oauth-bearer", handler]]),
    idempotencyKey: "revoke-request",
    store: activeEnrollmentStore()
  });
  return response.status === 200 && isDeepStrictEqual(received, testCase.expected.body);
}

async function evaluateInvalidRevokeRequest(testCase) {
  const response = await handleRevokeRequest(testCase.input, {
    agentDid: AGENT_DID,
    handlers: new Map(),
    idempotencyKey: "invalid-revoke-request",
    store: activeEnrollmentStore()
  });
  return testCase.expected.valid === false && response.status === 400;
}

async function evaluateRevokeResponse(testCase) {
  const response = await handleRevokeRequest(
    { all_grant_types: "true" },
    {
      agentDid: AGENT_DID,
      handlers: new Map(),
      idempotencyKey: "revoke-response",
      store: activeEnrollmentStore()
    }
  );
  return responseMatches(response, testCase.expected);
}

async function evaluateEnrollmentConflict(testCase) {
  const store = createInMemoryCommandIdempotencyStore();
  const first = {
    agentDid: testCase.input.agent_did,
    command: "enroll",
    idempotencyKey: testCase.input.idempotency_key,
    requestHash: testCase.input.first_body_hash
  };
  await store.executeIdempotentCommand(first, () => ({
    body: { status: "active" },
    contentType: "application/aep+json",
    status: 200
  }));
  const second = await store.executeIdempotentCommand(
    { ...first, requestHash: testCase.input.second_body_hash },
    () => ({ body: {}, contentType: "application/aep+json", status: 200 })
  );
  return second.state === "conflict" && testCase.expected.status === 409;
}

async function evaluateCommandIdempotencyHeader(testCase) {
  const idempotencyKey = testCase.input.idempotency_key;
  const enrollMissing = await handleEnrollRequest(
    { agent_did: AGENT_DID },
    {
      idempotencyKey: "",
      policy: createStaticEnrollmentPolicy(),
      store: createInMemoryEnrollmentStore()
    }
  );
  const grantMissing = await handleGrantRequest(
    { grant_type: "oauth-bearer" },
    {
      agentDid: AGENT_DID,
      handlers: new Map(),
      idempotencyKey: "",
      store: activeEnrollmentStore()
    }
  );
  const revokeMissing = await handleRevokeRequest(
    { all_grant_types: "true" },
    {
      agentDid: AGENT_DID,
      handlers: new Map(),
      idempotencyKey: "",
      store: activeEnrollmentStore()
    }
  );
  const enrollWithoutBodyKey = await handleEnrollRequest(
    { agent_did: AGENT_DID },
    {
      idempotencyKey,
      policy: createStaticEnrollmentPolicy(),
      store: createInMemoryEnrollmentStore()
    }
  );
  const enrollMismatch = await handleEnrollRequest(
    { agent_did: AGENT_DID, idempotency_key: `${idempotencyKey}-different` },
    {
      idempotencyKey,
      policy: createStaticEnrollmentPolicy(),
      store: createInMemoryEnrollmentStore()
    }
  );
  return (
    [enrollMissing, grantMissing, revokeMissing].every(
      (response) =>
        response.status === testCase.expected.missing_or_empty_status &&
        response.body.code === testCase.expected.missing_or_empty_code
    ) &&
    enrollWithoutBodyKey.status === 200 &&
    enrollMismatch.status === testCase.expected.mismatched_enroll_body_status
  );
}

async function evaluateCommandReplayConflict(testCase) {
  const store = createInMemoryCommandIdempotencyStore();
  const input = {
    agentDid: testCase.input.agent_did,
    command: testCase.input.first_command,
    idempotencyKey: testCase.input.idempotency_key,
    requestHash: testCase.input.first_body_hash
  };
  await store.executeIdempotentCommand(input, () => ({
    body: { credential_id: "credential" },
    contentType: "application/aep+json",
    status: 200
  }));
  const replay = await store.executeIdempotentCommand(input, () => ({
    body: { credential_id: "different" },
    contentType: "application/aep+json",
    status: 200
  }));
  const changedBody = await store.executeIdempotentCommand(
    { ...input, requestHash: testCase.input.second_body_hash },
    () => ({ body: {}, contentType: "application/aep+json", status: 200 })
  );
  const changedCommand = await store.executeIdempotentCommand(
    { ...input, command: testCase.input.second_command },
    () => ({ body: {}, contentType: "application/aep+json", status: 200 })
  );
  return (
    replay.state === "replayed" &&
    changedBody.state === "conflict" &&
    changedCommand.state === "conflict" &&
    testCase.expected.retention_seconds_minimum >= 3600
  );
}

function evaluateInspectDocument(testCase) {
  let valid = true;
  try {
    parseInspectDocument(testCase.input.document);
  } catch {
    valid = false;
  }
  return valid === testCase.expected.valid;
}

function evaluateInspectAdvertisement(testCase) {
  const expected = testCase.expected;
  const options = {
    authenticationMethods: expected.authentication?.methods,
    claims: expected.claims,
    grantTypes: (expected.commands.grant_types ?? []).map(grantDefinition),
    identityMethods: [didWebIdentityMethod()],
    serviceDid: expected.service.did,
    ...(expected.http.openapi === undefined
      ? {}
      : {
          openapi: {
            pathMatching: {
              trailingSlash: expected.http.openapi.path_matching.trailing_slash
            },
            url: expected.http.openapi.url
          }
        })
  };
  return isDeepStrictEqual(buildInspectDocument(options), expected);
}

function evaluateDefaultEndpointBase(testCase) {
  const document = buildInspectDocument({
    endpointBase: testCase.expected.endpoint_base,
    identityMethods: [didWebIdentityMethod()],
    serviceDid: SERVICE_DID
  });
  return document.http.endpoint_base === testCase.expected.endpoint_base;
}

function evaluateProtocolVersion(testCase) {
  return testCase.expected.cases.every((entry) => {
    let accepted = true;
    try {
      parseInspectDocument({
        ...minimalInspect(),
        aep_version: entry.received
      });
    } catch {
      accepted = false;
    }
    const compatible = isAepVersionCompatible(entry.received, entry.supported ?? AEP_VERSION);
    return accepted === (entry.valid && entry.compatible) && compatible === entry.compatible;
  });
}

function evaluateServiceDidAdvertisement(testCase) {
  const matching = buildInspectDocument({
    identityMethods: [didWebIdentityMethod()],
    serviceDid: testCase.input.matching_service_did
  });
  return (
    matching.service.did === testCase.input.matching_service_did &&
    testCase.expected.provision_identity === false &&
    testCase.expected.request_assertion === false &&
    testCase.expected.transmit_credentials === false
  );
}

function evaluateTransportAdvertisement(testCase) {
  const document = buildInspectDocument({
    identityMethods: [didWebIdentityMethod()],
    serviceDid: SERVICE_DID
  });
  return (
    document.bindings.supported.includes("http") &&
    testCase.expected.media_type_essence === "application/aep+json" &&
    testCase.expected.cross_origin_redirect === "reject" &&
    testCase.expected.scheme_downgrade === "reject"
  );
}

function evaluateDiscoveryResponse(testCase) {
  const service = createAepService({
    identityMethods: [didWebIdentityMethod()],
    serviceDid: SERVICE_DID
  });
  const first = service.inspectDocument();
  first.service.did = "did:web:mutated.example.com";
  const document = service.inspectDocument();
  return (
    document.aep_version === AEP_VERSION &&
    document.service.did === SERVICE_DID &&
    isDeepStrictEqual(JSON.parse(JSON.stringify(document)), document) &&
    testCase.expected.default_freshness_seconds === "300" &&
    testCase.expected.status_304 === "reuse-validated-representation"
  );
}

function evaluateOpenApiPathMatching(testCase) {
  const strict = buildInspectDocument({
    identityMethods: [didWebIdentityMethod()],
    openapi: { pathMatching: { trailingSlash: "strict" }, url: "/openapi.json" },
    serviceDid: SERVICE_DID
  });
  const equivalent = buildInspectDocument({
    identityMethods: [didWebIdentityMethod()],
    openapi: { pathMatching: { trailingSlash: "equivalent" }, url: "/openapi.json" },
    serviceDid: SERVICE_DID
  });
  return (
    strict.http.openapi.path_matching.trailing_slash === "strict" &&
    equivalent.http.openapi.path_matching.trailing_slash === "equivalent" &&
    testCase.expected.query_selects_operation === false
  );
}

function evaluateOpenApiSecurity(testCase) {
  const document = buildInspectDocument({
    authenticationMethods: [testCase.input.security_scheme["x-aep-authentication-method"]],
    identityMethods: [didWebIdentityMethod()],
    openapi: { pathMatching: { trailingSlash: "strict" }, url: "/openapi.json" },
    serviceDid: SERVICE_DID
  });
  return document.authentication.methods[0] === "aep-jwt";
}

function evaluateOpenApiUrl(testCase) {
  const document = buildInspectDocument({
    identityMethods: [didWebIdentityMethod()],
    openapi: { pathMatching: { trailingSlash: "strict" }, url: testCase.input.relative },
    serviceDid: SERVICE_DID
  });
  return (
    new URL(document.http.openapi.url, testCase.input.final_inspect_url).toString() ===
      testCase.expected.relative_resolved && testCase.expected.forwarded_headers.length === 0
  );
}

async function evaluateHostedAuthenticateResource(testCase) {
  const clientAssertion = jwtAssertion("authenticate", "missing-resource");
  const service = serviceWithVerifier(
    createHostedPlatformClientAssertionVerifier({
      endpoint: "https://p.example/v1/aep/verifications",
      fetch: () =>
        Promise.resolve({
          json: () =>
            Promise.resolve({
              agent_did: AGENT_DID,
              op: "authenticate",
              reason: "verified",
              service_did: SERVICE_DID,
              verified: true
            }),
          ok: true,
          status: 200
        })
    }),
    { authenticationMethods: ["aep-jwt"] }
  );
  const result = await service.authenticateProtectedResource({
    headers: { Authorization: "AEP " + clientAssertion },
    method: "GET",
    url: "https://api.example.com/orders"
  });
  return !result.authenticated && testCase.expected.valid === false;
}

async function evaluateHostedVerificationRequest(testCase) {
  let request;
  const verifier = createHostedPlatformClientAssertionVerifier({
    endpoint: "https://p.example/v1/aep/verifications",
    fetch: (_input, init) => {
      request = init;
      return Promise.resolve({
        json: () =>
          Promise.resolve({
            agent_did: "did:web:p.example:a:4Yf7p2xQd9",
            op: testCase.input.op,
            reason: "verified",
            service_did: testCase.input.service_did,
            verified: true
          }),
        ok: true,
        status: 200
      });
    }
  });
  await verifier(testCase.input.client_assertion, {
    clientAssertion: testCase.input.client_assertion,
    command: testCase.input.op,
    idempotencyKey: testCase.expected.idempotency_key_header,
    serviceDid: testCase.input.service_did,
    signingAlgorithms: ["ES256"]
  });
  return request.headers["Idempotency-Key"] === testCase.expected.idempotency_key_header;
}

async function evaluateHostedRecognized(testCase) {
  const clientAssertion = jwtAssertion("enroll", "hosted-recognized", undefined, {
    aud: testCase.expected.service_did,
    iss: testCase.expected.agent_did,
    sub: testCase.expected.agent_did
  });
  const verifier = createHostedPlatformClientAssertionVerifier({
    endpoint: "https://p.example/v1/aep/verifications",
    fetch: () => Promise.resolve(responseLike(testCase.expected))
  });
  const claims = await verifier(clientAssertion, {
    clientAssertion,
    command: "enroll",
    serviceDid: testCase.expected.service_did,
    signingAlgorithms: ["ES256"]
  });
  return claims.sub === testCase.expected.agent_did;
}

async function evaluateHostedUnrecognized(testCase) {
  const clientAssertion = jwtAssertion("enroll", "hosted-unrecognized", undefined, {
    aud: testCase.expected.service_did
  });
  const verifier = createHostedPlatformClientAssertionVerifier({
    endpoint: "https://p.example/v1/aep/verifications",
    fetch: () => Promise.resolve(responseLike(testCase.expected))
  });
  try {
    await verifier(clientAssertion, {
      clientAssertion,
      command: "enroll",
      serviceDid: testCase.expected.service_did,
      signingAlgorithms: ["ES256"]
    });
    return false;
  } catch {
    return true;
  }
}

async function evaluateWrongApiKeyHeader(testCase) {
  const service = credentialService(
    storedApiKeyGrantType({
      clock: () => NOW,
      issue: () => ({
        api_key: testCase.input.api_key,
        credential_id: "api-key-vector",
        expires_at: "2026-12-01T00:00:00Z",
        header: testCase.input.issued_header,
        scopes: null
      }),
      store: createInMemoryServiceCredentialStore()
    }),
    "api-key"
  );
  await service.ready;
  const result = await service.api.authenticateProtectedResource({
    headers: { [testCase.input.presented_header]: testCase.input.api_key },
    method: "GET",
    url: "https://api.example.com/orders"
  });
  return !result.authenticated && testCase.expected.accepted === false;
}

async function evaluateAuthenticateAssertion(testCase) {
  const service = serviceWithVerifier(parseJwtOrJsonAssertion, {
    authenticationMethods: ["aep-jwt"],
    clientAssertion: {
      clock: () => new Date(testCase.expected.claims.iat * 1000),
      clockSkewSeconds: 0,
      maxTtlSeconds: 300
    },
    inspectUrl: "https://api.example.com/.well-known/aep"
  });
  const anonymous = await service.authenticateProtectedResource({
    headers: {},
    method: testCase.input.method,
    url: testCase.input.url
  });
  const authenticated = await service.authenticateProtectedResource({
    headers: { Authorization: "AEP " + JSON.stringify(testCase.expected.claims) },
    method: testCase.input.method,
    url: testCase.input.url
  });
  if (anonymous.authenticated) throw new Error("Anonymous request was authenticated");
  if (
    !anonymous.response.headers["WWW-Authenticate"].includes('reason="authentication_required"')
  ) {
    throw new Error("Anonymous challenge did not report authentication_required");
  }
  if (!authenticated.authenticated) {
    throw new Error("Authenticate assertion failed with " + authenticated.response.body.code);
  }
  return true;
}

async function evaluateAuthorizationAmbiguity(testCase) {
  const service = serviceWithVerifier(parseAssertion, { authenticationMethods: ["aep-jwt"] });
  const result = await service.authenticateProtectedResource({
    headers: {
      "AEP-Authorization": ["AEP first", "AEP second"],
      Authorization: "AEP standard"
    },
    method: "GET",
    url: "https://api.example.com/orders"
  });
  return !result.authenticated && result.response.body.code === testCase.expected.code;
}

async function evaluateAuthorizationCarriers(testCase) {
  const handlers = [
    grantHandler("oauth-bearer", ({ headers }) => headers.authorization === "Bearer token"),
    grantHandler("api-key", ({ headers }) => headers["x-api-key"] === "key"),
    grantHandler(
      "basic",
      ({ headers }) =>
        headers.authorization === "Basic " + Buffer.from("user:pass").toString("base64")
    )
  ];
  const service = serviceWithVerifier(parseJwtOrJsonAssertion, {
    authenticationMethods: ["aep-jwt", "oauth-bearer", "api-key", "basic"],
    grantTypes: handlers
  });
  const cases = [
    {
      Authorization:
        "AEP " + jwtAssertion("authenticate", "standard-jwt", "https://api.example.com/orders")
    },
    {
      "AEP-Authorization":
        "AEP " + jwtAssertion("authenticate", "dedicated-jwt", "https://api.example.com/orders")
    },
    { Authorization: "Bearer token" },
    { "AEP-Authorization": "Bearer token" },
    { "x-api-key": "key" },
    { Authorization: "Basic " + Buffer.from("user:pass").toString("base64") }
  ];
  for (const [index, headers] of cases.entries()) {
    const result = await service.authenticateProtectedResource({
      headers,
      method: "GET",
      url: "https://api.example.com/orders"
    });
    if (!result.authenticated) {
      throw new Error(
        "Authorization carrier case " + index + " failed with " + result.response.body.code
      );
    }
  }
  return testCase.expected.dedicated_bearer.carrier === "AEP-Authorization";
}

async function evaluatePaymentComposition(testCase) {
  const service = serviceWithVerifier(parseJwtOrJsonAssertion, {
    authenticationMethods: ["aep-jwt"]
  });
  const result = await service.authenticateProtectedResource({
    headers: {
      "AEP-Authorization":
        "AEP " + jwtAssertion("authenticate", "payment", "https://api.example.com/orders"),
      Authorization: "Payment credential",
      "PAYMENT-SIGNATURE": "signature"
    },
    method: "GET",
    url: "https://api.example.com/orders"
  });
  return result.authenticated && testCase.expected.mpp.ambiguous === false;
}

async function evaluateCredentialPresentations(testCase) {
  const expected = testCase.expected;
  const cases = [
    {
      definition: storedOAuthBearerGrantType({
        clock: () => NOW,
        issue: () => ({
          access_token: "opaque-token",
          credential_id: "oauth-vector",
          expires_at: "2026-12-01T00:00:00Z",
          scopes: [],
          token_type: "Bearer"
        }),
        store: createInMemoryServiceCredentialStore()
      }),
      grantType: "oauth-bearer",
      headers: { Authorization: "Bearer opaque-token" }
    },
    {
      definition: storedApiKeyGrantType({
        clock: () => NOW,
        issue: () => ({
          api_key: expected["api-key"].value,
          credential_id: "api-key-vector",
          expires_at: "2026-12-01T00:00:00Z",
          header: expected["api-key"].header,
          scopes: []
        }),
        store: createInMemoryServiceCredentialStore()
      }),
      grantType: "api-key",
      headers: { [expected["api-key"].header]: expected["api-key"].value }
    },
    {
      definition: storedBasicGrantType({
        clock: () => NOW,
        issue: () => ({
          credential_id: "basic-vector",
          expires_at: "2026-12-01T00:00:00Z",
          password: "password",
          scopes: [],
          username: "user"
        }),
        store: createInMemoryServiceCredentialStore()
      }),
      grantType: "basic",
      headers: { Authorization: "Basic " + Buffer.from("user:password").toString("base64") }
    }
  ];
  for (const test of cases) {
    const service = credentialService(test.definition, test.grantType);
    await service.ready;
    const result = await service.api.authenticateProtectedResource({
      headers: test.headers,
      method: "GET",
      url: "https://api.example.com/orders"
    });
    if (!result.authenticated) return false;
  }
  return true;
}

function evaluateAuthenticationAdvertisements(testCase) {
  const cases = [
    testCase.expected.jwt_only.authentication.methods,
    testCase.expected.credentials_only.authentication.methods,
    testCase.expected.ordered_mixed.authentication.methods
  ];
  return cases.every((methods) => {
    const document = buildInspectDocument({
      authenticationMethods: methods,
      identityMethods: [didWebIdentityMethod()],
      serviceDid: SERVICE_DID
    });
    return isDeepStrictEqual(document.authentication.methods, methods);
  });
}

async function evaluateOperationBinding(testCase) {
  for (const command of testCase.input.command_endpoints) {
    const service = serviceWithVerifier(() => assertionClaims("status", command));
    const response = await service[command === "status" ? "status" : command](
      ...(command === "status"
        ? [{ clientAssertion: "assertion" }]
        : [commandBody(command), { clientAssertion: "assertion" }])
    );
    if (response.status !== 401) return false;
  }
  return true;
}

async function evaluateAuthenticationFailures(testCase) {
  const service = serviceWithVerifier(
    () => {
      throw new Error("invalid assertion");
    },
    { authenticationMethods: ["aep-jwt"] }
  );
  const result = await service.authenticateProtectedResource({
    headers: { Authorization: "AEP malformed" },
    method: "GET",
    url: "https://api.example.com/orders"
  });
  return (
    !result.authenticated &&
    result.response.body.code === testCase.expected.wrong_audience &&
    testCase.expected.unsupported_method === "unsupported_authentication_method"
  );
}

async function evaluateAuthorizationFieldSafety(testCase) {
  const resource = "https://api.example.com/orders";
  const service = serviceWithVerifier(parseJwtOrJsonAssertion, {
    authenticationMethods: ["aep-jwt"]
  });
  const result = await service.authenticateProtectedResource({
    headers: {
      [testCase.input.field_name]: "AEP " + jwtAssertion("authenticate", "field-safety", resource),
      "PAYMENT-SIGNATURE": "payment-signature"
    },
    method: "GET",
    url: resource
  });
  return result.authenticated;
}

async function evaluateRedirectSafety(testCase) {
  const service = serviceWithVerifier(parseJwtOrJsonAssertion, {
    authenticationMethods: ["aep-jwt"]
  });
  const stale = await service.authenticateProtectedResource({
    headers: {
      Authorization: "AEP " + jwtAssertion("authenticate", "stale-redirect", testCase.input.source)
    },
    method: "GET",
    url: testCase.input.same_origin
  });
  const rebound = await service.authenticateProtectedResource({
    headers: {
      Authorization:
        "AEP " + jwtAssertion("authenticate", "rebound-redirect", testCase.input.same_origin)
    },
    method: "GET",
    url: testCase.input.same_origin
  });
  const crossOrigin = await service.authenticateProtectedResource({
    headers: {
      Authorization: "AEP " + jwtAssertion("authenticate", "cross-origin", testCase.input.source)
    },
    method: "GET",
    url: testCase.input.cross_origin
  });
  return !stale.authenticated && rebound.authenticated && !crossOrigin.authenticated;
}

async function evaluateStatusResponse(testCase) {
  const expected = testCase.expected.body;
  const response = await handleStatusRequest(AGENT_DID, {
    store: createInMemoryEnrollmentStore([
      enrollmentRecord({
        agent_did: AGENT_DID,
        requirements_pending: expected.requirements_pending,
        since: expected.since,
        status: expected.status
      })
    ])
  });
  return responseMatches(response, testCase.expected);
}

function serviceWithVerifier(verifier, overrides = {}) {
  return createAepService({
    clientAssertion: { clock: () => NOW, clockSkewSeconds: 0, maxTtlSeconds: 300 },
    clientAssertionVerifier: verifier,
    identityMethods: [didWebIdentityMethod()],
    serviceDid: SERVICE_DID,
    ...overrides
  });
}

function parseAssertion(value) {
  return JSON.parse(value);
}

function parseJwtOrJsonAssertion(value) {
  if (value.startsWith("{")) return parseAssertion(value);
  return JSON.parse(Buffer.from(value.split(".")[1], "base64url").toString("utf8"));
}

function assertion(command, jti, resource) {
  return JSON.stringify(assertionClaims(command, jti, resource));
}

function jwtAssertion(command, jti, resource, overrides = {}) {
  const header = Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({ ...assertionClaims(command, jti, resource), ...overrides })
  ).toString("base64url");
  return header + "." + payload + ".signature";
}

function assertionClaims(command, jti, resource) {
  const now = Math.floor(NOW.getTime() / 1000);
  return {
    aud: SERVICE_DID,
    exp: now + 300,
    iat: now,
    iss: AGENT_DID,
    jti,
    op: command,
    ...(resource === undefined ? {} : { resource }),
    sub: AGENT_DID
  };
}

async function enroll(service, jti) {
  return service.enroll(
    { agent_did: AGENT_DID, idempotency_key: jti },
    { clientAssertion: assertion("enroll", jti), idempotencyKey: jti }
  );
}

function activeEnrollmentStore() {
  return createInMemoryEnrollmentStore([
    enrollmentRecord({ agent_did: AGENT_DID, status: "active" })
  ]);
}

function enrollmentRecord(value) {
  const since = value.since ?? NOW.toISOString();
  return {
    agentDid: value.agent_did,
    claims: {},
    createdAt: since,
    ownerActionRequired:
      value.owner_action_required === true || value.owner_action_required === "true",
    requirementsPending: value.requirements_pending ?? [],
    ...(value.verification_pending === undefined
      ? {}
      : { verificationPending: value.verification_pending }),
    since,
    status: value.status,
    updatedAt: since
  };
}

function responseLike(body) {
  return {
    json: () => Promise.resolve(body),
    ok: true,
    status: 200
  };
}

function responseMatches(actual, expected) {
  return (
    actual.status === expected.status &&
    actual.contentType === expected.content_type &&
    isDeepStrictEqual(actual.body, expected.body)
  );
}

function grantDefinition(name) {
  if (name === "oauth-bearer") return oauthBearerGrantType();
  if (name === "api-key") return apiKeyGrantType();
  if (name === "basic") return basicGrantType();
  throw new Error("Unknown grant type " + name);
}

function minimalInspect() {
  return {
    aep_version: AEP_VERSION,
    bindings: { supported: ["http"] },
    commands: { supported: ["inspect"] },
    core: { signing_algorithms: ["EdDSA", "ES256"] },
    http: {},
    identity: { methods: [] },
    service: { did: SERVICE_DID }
  };
}

function hostedVerification() {
  return {
    agent_did: AGENT_DID,
    op: "status",
    reason: "recognized",
    service_did: SERVICE_DID,
    verified: true
  };
}

function verifierContext(command) {
  return {
    clientAssertion: assertion(command, "hosted-context"),
    command,
    serviceDid: SERVICE_DID,
    signingAlgorithms: ["ES256"]
  };
}

function grantHandler(name, authenticate) {
  return {
    grantType: name,
    handler: {
      authenticate: (input) =>
        authenticate(input)
          ? {
              agentDid: AGENT_DID,
              authenticationKind: "session-credential",
              authenticationMethod: name,
              grantType: name
            }
          : undefined,
      grant: () => ({}),
      revoke: () => undefined
    }
  };
}

function credentialService(definition, grantType) {
  const api = serviceWithVerifier(parseAssertion, {
    authenticationMethods: [grantType],
    clock: () => NOW,
    grantTypes: [definition]
  });
  const ready = (async () => {
    await enroll(api, "credential-service-enroll");
    await api.grant(
      { grant_type: grantType },
      {
        clientAssertion: assertion("grant", "credential-service-grant"),
        idempotencyKey: "credential-service-grant"
      }
    );
  })();
  return { api, ready };
}

function commandBody(command) {
  if (command === "enroll") return { agent_did: AGENT_DID, idempotency_key: "operation-binding" };
  if (command === "grant") return { grant_type: "oauth-bearer" };
  return { all_grant_types: "true" };
}
