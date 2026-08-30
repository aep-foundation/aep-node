#!/usr/bin/env node

import { generateKeyPairSync } from "node:crypto";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";

import {
  AepClaimRequirementsError,
  AepClaimValuesError,
  AepCommandError,
  AepInspectError,
  buildClientAssertionClaims,
  clientAssertionAuthenticationHeaders,
  createJwtClientAssertionSigner,
  createInMemoryPublicDocumentCache,
  createPlatformDelegatedSigner,
  credentialPresentationHeaders,
  discoverPlatform,
  enrollService,
  fetchProtectedResource,
  grantService,
  inspectOpenApiPolicy,
  inspectService,
  interpretAepOpenApiOperation,
  listPlatformIdentities,
  protectedResourceAuthenticationHeaders,
  provisionPlatformIdentity,
  revokeService,
  signClientAssertion,
  statusService
} from "../packages/agent/dist/index.js";

const SERVICE_ORIGIN = "https://api.example.com";
const SERVICE_DID = "did:web:api.example.com";
const PLATFORM_ORIGIN = "https://p.example";
const AGENT_DID = "did:web:agent.example.com:agents:123";
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

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });

for await (const line of input) {
  if (line.trim() === "") continue;
  const request = JSON.parse(line);
  const result = await evaluate(request);
  process.stdout.write(
    `${JSON.stringify({ protocol_version: "1", sequence: request.sequence, ...result })}\n`
  );
}

async function evaluate(request) {
  try {
    const passed = await evaluateCase(request.vector.id, request.case);
    return passed
      ? { status: "passed" }
      : { status: "failed", message: "Public Agent API result did not match the vector" };
  } catch (error) {
    return {
      status: "failed",
      message: error instanceof Error ? error.message.slice(0, 1024) : "Agent evaluation failed"
    };
  }
}

async function evaluateCase(id, testCase) {
  if (id === "public-discovery-cache") return evaluateDiscoveryCache(testCase);
  if (CLAIM_VALUE_VECTOR_IDS.has(id)) return evaluateClaimValue(testCase);
  switch (id) {
    case "person-contact-catalog":
      return evaluateClaimValue({
        input: { claim_values: testCase.expected },
        expected: { valid: true }
      });
    case "negotiation-compatibility":
      return evaluateClaimNegotiation(testCase);
    case "unknown-required-claim":
      return evaluateUnknownRequiredClaim(testCase);
    case "enroll-claims":
      return isDeepStrictEqual(
        buildClientAssertionClaims({
          agentDid: testCase.input.agent_did,
          clock: () => new Date(testCase.input.issued_at * 1000),
          command: testCase.input.command,
          jti: testCase.input.jti,
          serviceDid: testCase.input.service_did,
          ttlSeconds: testCase.input.expires_at - testCase.input.issued_at
        }),
        testCase.expected
      );
    case "validation-requirements":
      return evaluateClientAssertionValidation(testCase);
    case "command-header":
      return evaluateCommandIdempotencyHeader(testCase);
    case "request-minimal":
    case "request-claims-catalog":
      return evaluateEnrollRequest(testCase);
    case "response-active":
      return evaluateLifecycleResponse(testCase);
    case "response-pending-verification-owner-action":
      return evaluateEnrollResponse(testCase);
    case "response-pending-requirements":
      return evaluateStatusResponse(testCase);
    case "grant-response":
      return evaluateGrantResponse(testCase);
    case "grant-request-oauth-bearer":
      return evaluateGrantRequest(testCase);
    case "revoke-request-all-grant-types":
    case "revoke-request-oauth-bearer":
      return evaluateRevokeRequest(testCase);
    case "revoke-response-empty":
      return evaluateRevokeResponse(testCase);
    case "not-recognized-problem":
    case "requirements-unmet-problem":
    case "verification-pending-problem":
      return evaluateProblem(testCase);
    case "grant-before-enroll-rejected":
      return evaluateGrantBeforeEnroll(testCase);
    case "authenticated-command-without-identity-method":
    case "authentication-method-limit":
    case "command-without-inspect":
    case "forward-compatible-advertisements":
    case "grant-without-grant-types":
    case "invalid-advertisement-identifiers":
    case "invalid-openapi-reference":
    case "missing-signing-algorithm":
      return evaluateInspectDocument(testCase.input.document, testCase.expected.valid);
    case "claims-catalog-advertisement":
    case "minimal-http":
      return evaluateInspectDocument(testCase.expected, true);
    case "default-endpoint-base":
      return evaluateDefaultEndpointBase(testCase);
    case "protocol-version":
      return evaluateProtocolVersions(testCase);
    case "service-did-origin-binding":
      return evaluateServiceDidBinding(testCase);
    case "transport-requirements":
      return evaluateTransport(testCase);
    case "path-matching":
      return evaluateOpenApiPathMatching(testCase);
    case "security-inheritance":
      return evaluateOpenApiSecurity(testCase);
    case "url-resolution":
      return evaluateOpenApiUrlResolution(testCase);
    case "discovery":
      return evaluatePlatformDiscovery(testCase);
    case "provision-request":
      return evaluatePlatformProvisionRequest(testCase);
    case "provision-response":
      return evaluatePlatformProvisionResponse(testCase);
    case "provision-response-distinct-services":
      return evaluateDistinctPlatformIdentities(testCase);
    case "list-response":
      return evaluatePlatformList(testCase);
    case "sign-request":
      return evaluatePlatformSignRequest(testCase);
    case "sign-response":
    case "sign-response-pending":
      return evaluatePlatformSignResponse(testCase);
    case "idempotency-replay-conflict":
      return evaluatePlatformConflict(testCase);
    case "credential-presentations":
      return evaluateCredentialPresentations(testCase);
    case "authenticate-assertion":
      return evaluateAuthenticateAssertion(testCase);
    case "authorization-carriers":
      return evaluateAuthorizationCarriers(testCase);
    case "authorization-payment-composition":
      return evaluatePaymentComposition(testCase);
    case "api-key-wrong-header-rejected":
      return evaluateApiKeyHeader(testCase);
    case "inspect-authentication-methods":
      return evaluateAuthenticationMethods(testCase);
    case "operation-substitution-rejected":
      return evaluateOperationBinding(testCase);
    case "assertion-and-credential-failures":
    case "authorization-ambiguity":
    case "authorization-field-safety":
    case "redirect-safety":
      return evaluateProtectedResourceSafety(id, testCase);
    default:
      throw new Error(`No Agent operation maps vector ${id}`);
  }
}

async function evaluateCommandIdempotencyHeader(testCase) {
  const idempotencyKey = testCase.input.idempotency_key;
  const inspect = inspectResult();
  const calls = [
    await captureCommand(() =>
      enrollService({
        agentDid: AGENT_DID,
        clientAssertion: "assertion",
        idempotencyKey,
        inspect,
        serviceUrl: SERVICE_ORIGIN
      })
    ),
    await captureCommand(
      () =>
        grantService({
          clientAssertion: "assertion",
          grantType: "oauth-bearer",
          idempotencyKey,
          inspect,
          serviceUrl: SERVICE_ORIGIN
        }),
      grantResponse("oauth-bearer")
    ),
    await captureCommand(
      () =>
        revokeService({
          allGrantTypes: true,
          clientAssertion: "assertion",
          idempotencyKey,
          inspect,
          serviceUrl: SERVICE_ORIGIN
        }),
      {}
    )
  ];
  const enrollBody = JSON.parse(calls[0].init.body);
  return (
    testCase.expected.header_required === true &&
    calls.every((call) => new Headers(call.init.headers).get("idempotency-key") === idempotencyKey) &&
    enrollBody.idempotency_key === idempotencyKey
  );
}

async function evaluateClientAssertionValidation(testCase) {
  const { privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" }
  });
  const signer = createJwtClientAssertionSigner({
    alg: testCase.input.algorithm,
    key: { format: "pkcs8", pem: privateKey }
  });
  const base = {
    agentDid: testCase.input.agent_did,
    clock: () => new Date(testCase.input.issued_at * 1000),
    jti: testCase.input.jti,
    serviceDid: testCase.input.service_did
  };
  const jwt = await signClientAssertion({
    ...base,
    command: "enroll",
    signer,
    ttlSeconds: testCase.input.expires_at - testCase.input.issued_at
  });
  const [encodedHeader, encodedPayload] = jwt.split(".");
  if (encodedHeader === undefined || encodedPayload === undefined) return false;
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));

  if (
    !isDeepStrictEqual(header, testCase.expected.header) ||
    !isDeepStrictEqual(claims, testCase.expected.claims)
  ) {
    return false;
  }

  const invalidClaims = [
    { ...base, command: "enroll", ttlSeconds: 301 },
    { ...base, command: "enroll", ttlSeconds: 0 },
    { ...base, command: "authenticate" },
    { ...base, command: "enroll", resource: "https://api.example.com/orders" },
    { ...base, command: "authenticate", resource: "http://api.example.com/orders" },
    { ...base, command: "authenticate", resource: "https://api.example.com/orders#item" }
  ];

  if (!invalidClaims.every((options) => throws(() => buildClientAssertionClaims(options)))) {
    return false;
  }

  const mismatchedSigner = createJwtClientAssertionSigner({
    alg: testCase.input.algorithm,
    key: { format: "pkcs8", pem: privateKey },
    kid: "did:web:different.example.com#key-1"
  });

  try {
    await signClientAssertion({ ...base, command: "enroll", signer: mismatchedSigner });
    return false;
  } catch {
    return true;
  }
}

function throws(operation) {
  try {
    operation();
    return false;
  } catch {
    return true;
  }
}

async function evaluateClaimValue(testCase) {
  const inspect = inspectResult({ claims: { optional: [], preferred: [], required: [] } });
  let valid = true;
  try {
    await enrollService({
      agentDid: "did:web:agent.example.com:agents:123",
      claims: testCase.input.claim_values,
      clientAssertion: "assertion",
      fetch: () => jsonResponse({ status: "active" }),
      idempotencyKey: "claim-vector",
      inspect,
      serviceUrl: SERVICE_ORIGIN
    });
  } catch (error) {
    if (!(error instanceof AepClaimValuesError)) throw error;
    valid = false;
  }
  return valid === testCase.expected.valid;
}

async function evaluateClaimNegotiation(testCase) {
  let called = false;
  const inspect = inspectResult({ claims: testCase.input.inspect });
  await enrollService({
    agentDid: AGENT_DID,
    claims: testCase.input.submitted,
    clientAssertion: "assertion",
    fetch: () => {
      called = true;
      return jsonResponse({ status: "active" });
    },
    idempotencyKey: "claims-negotiation",
    inspect,
    serviceUrl: SERVICE_ORIGIN
  });
  return called && testCase.expected.enrollment_requirement_satisfied;
}

async function evaluateUnknownRequiredClaim(testCase) {
  try {
    await enrollService({
      agentDid: AGENT_DID,
      clientAssertion: "assertion",
      fetch: () => jsonResponse({ status: "active" }),
      idempotencyKey: "unknown-required",
      inspect: inspectResult({
        claims: { optional: [], preferred: [], required: testCase.input.required }
      }),
      serviceUrl: SERVICE_ORIGIN
    });
    return testCase.expected.can_satisfy;
  } catch (error) {
    return error instanceof AepClaimRequirementsError && !testCase.expected.can_satisfy;
  }
}

async function evaluateEnrollRequest(testCase) {
  const call = await captureCommand(() =>
    enrollService({
      agentDid: testCase.input.agent_did,
      claims: testCase.input.claims,
      clientAssertion: "client-assertion",
      idempotencyKey: testCase.input.idempotency_key,
      inspect: inspectResult({ claims: { optional: [], preferred: [], required: [] } }),
      serviceUrl: SERVICE_ORIGIN
    })
  );
  return requestMatches(call, testCase.expected, "client-assertion");
}

async function evaluateEnrollResponse(testCase) {
  const result = await enrollService({
    agentDid: AGENT_DID,
    clientAssertion: "assertion",
    fetch: () => responseFromExpectation(testCase.expected),
    idempotencyKey: "enroll-response",
    inspect: inspectResult(),
    serviceUrl: SERVICE_ORIGIN
  });
  return (
    result.status === testCase.expected.status &&
    isDeepStrictEqual(result.body, testCase.expected.body)
  );
}

async function evaluateLifecycleResponse(testCase) {
  return "enrollment_mode" in testCase.input
    ? evaluateEnrollResponse(testCase)
    : evaluateStatusResponse(testCase);
}

async function evaluateStatusResponse(testCase) {
  const result = await statusService({
    clientAssertion: "assertion",
    fetch: () => responseFromExpectation(testCase.expected),
    inspect: inspectResult(),
    serviceUrl: SERVICE_ORIGIN
  });
  return (
    result.status === testCase.expected.status &&
    isDeepStrictEqual(result.body, testCase.expected.body)
  );
}

async function evaluateGrantRequest(testCase) {
  const call = await captureCommand(
    () =>
      grantService({
        clientAssertion: "client-assertion",
        grantType: testCase.input.grant_type,
        idempotencyKey: "grant-request",
        inspect: inspectResult(),
        serviceUrl: SERVICE_ORIGIN
      }),
    grantResponse(testCase.input.grant_type)
  );
  return requestMatches(call, testCase.expected, "client-assertion");
}

async function evaluateGrantResponse(testCase) {
  const result = await grantService({
    clientAssertion: "assertion",
    fetch: () => jsonResponse(testCase.expected),
    grantType: testCase.input.grant_type,
    idempotencyKey: "grant-response",
    inspect: inspectResult(),
    requestedScopes: testCase.input.requested_scopes,
    serviceUrl: SERVICE_ORIGIN
  });
  const expected =
    testCase.expected.scopes === null || testCase.expected.scopes === undefined
      ? { ...testCase.expected, scopes: [] }
      : testCase.expected;
  return isDeepStrictEqual(result.body, expected);
}

async function evaluateRevokeRequest(testCase) {
  const selector =
    testCase.input.all_grant_types === "true"
      ? { allGrantTypes: true }
      : { grantType: testCase.input.grant_type };
  const call = await captureCommand(
    () =>
      revokeService({
        ...selector,
        clientAssertion: "client-assertion",
        idempotencyKey: "revoke-request",
        inspect: inspectResult(),
        serviceUrl: SERVICE_ORIGIN
      }),
    {}
  );
  return requestMatches(call, testCase.expected, "client-assertion");
}

async function evaluateRevokeResponse(testCase) {
  const result = await revokeService({
    allGrantTypes: true,
    clientAssertion: "assertion",
    fetch: () => responseFromExpectation(testCase.expected),
    idempotencyKey: "revoke-response",
    inspect: inspectResult(),
    serviceUrl: SERVICE_ORIGIN
  });
  return (
    result.status === testCase.expected.status &&
    isDeepStrictEqual(result.body, testCase.expected.body)
  );
}

async function evaluateProblem(testCase) {
  try {
    await statusService({
      clientAssertion: "assertion",
      fetch: () => responseFromExpectation(testCase.expected),
      inspect: inspectResult(),
      serviceUrl: SERVICE_ORIGIN
    });
    return false;
  } catch (error) {
    return (
      error instanceof AepCommandError &&
      error.status === testCase.expected.status &&
      isDeepStrictEqual(error.problem, testCase.expected.body)
    );
  }
}

async function evaluateGrantBeforeEnroll(testCase) {
  let calls = 0;
  try {
    await grantService({
      clientAssertion: "assertion",
      fetch: () => {
        calls += 1;
        return jsonResponse(
          {
            type: "urn:aep:error:not_recognized",
            title: "Not recognized",
            status: 401,
            code: "not_recognized"
          },
          401,
          "application/problem+json"
        );
      },
      grantType: "oauth-bearer",
      idempotencyKey: "grant-before-enroll",
      inspect: inspectResult(),
      serviceUrl: SERVICE_ORIGIN
    });
    return false;
  } catch (error) {
    return (
      error instanceof AepCommandError &&
      error.problem?.code === testCase.expected.code &&
      calls === 1
    );
  }
}

async function evaluateInspectDocument(document, expectedValid) {
  let valid = true;
  try {
    await inspectService({
      fetch: () => jsonResponse(document),
      serviceUrl: SERVICE_ORIGIN
    });
  } catch (error) {
    if (!(error instanceof AepInspectError)) throw error;
    valid = false;
  }
  return valid === expectedValid;
}

async function evaluateDefaultEndpointBase(testCase) {
  const result = await inspectWithDocument(testCase.expected.document);
  return (
    String(result.commandUrl("enroll")) ===
      `${SERVICE_ORIGIN}${testCase.expected.endpoint_base}enroll` && testCase.expected.valid
  );
}

async function evaluateProtocolVersions(testCase) {
  for (const item of testCase.expected.cases) {
    const document = { ...baseInspectDocument(), aep_version: item.received };
    let accepted = true;
    try {
      await inspectWithDocument(document);
    } catch (error) {
      if (!(error instanceof AepInspectError)) throw error;
      accepted = false;
    }
    if (accepted !== (item.valid && item.compatible)) return false;
  }
  return true;
}

async function evaluateServiceDidBinding(testCase) {
  const matching = await inspectService({
    fetch: () =>
      jsonResponse({
        ...baseInspectDocument(),
        service: { did: testCase.input.matching_service_did }
      }),
    serviceUrl: SERVICE_ORIGIN
  });
  const errors = [];
  for (const did of [
    testCase.input.mismatched_service_did,
    testCase.input.unsupported_service_did
  ]) {
    try {
      await inspectService({
        fetch: () => jsonResponse({ ...baseInspectDocument(), service: { did } }),
        serviceUrl: SERVICE_ORIGIN
      });
    } catch (error) {
      errors.push(error);
    }
  }
  return (
    matching.document.service.did === testCase.input.matching_service_did &&
    errors.every(
      (error) => error instanceof AepInspectError && error.code === "service_identity_mismatch"
    )
  );
}

async function evaluateTransport(testCase) {
  let call = 0;
  const result = await inspectService({
    fetch: (url) => {
      call += 1;
      if (call === 1)
        return Promise.resolve(
          new Response(null, { status: 302, headers: { location: testCase.input.redirect_url } })
        );
      return jsonResponse(baseInspectDocument(), 200, testCase.input.content_type, {
        url: String(url)
      });
    },
    serviceUrl: SERVICE_ORIGIN
  });
  let rejected = false;
  try {
    await inspectService({
      fetch: () =>
        Promise.resolve(
          new Response(null, { status: 302, headers: { location: "https://other.example/aep" } })
        ),
      serviceUrl: SERVICE_ORIGIN
    });
  } catch (error) {
    rejected = error instanceof AepInspectError && error.code === "invalid_redirect";
  }
  return result.finalUrl?.href === testCase.input.redirect_url && rejected;
}

async function evaluateDiscoveryCache() {
  const cache = createInMemoryPublicDocumentCache();
  let requests = 0;
  const fetch = (_url, init) => {
    requests += 1;
    if (requests === 2 && new Headers(init?.headers).get("if-none-match") === '"inspect-1"') {
      return Promise.resolve(
        new Response(null, { status: 304, headers: { "cache-control": "max-age=300" } })
      );
    }
    return jsonResponse(baseInspectDocument(), 200, "application/aep+json", {
      headers: { "cache-control": "no-cache", etag: '"inspect-1"' }
    });
  };
  const first = await inspectService({
    fetch,
    publicDocumentCache: cache,
    serviceUrl: SERVICE_ORIGIN
  });
  const second = await inspectService({
    fetch,
    publicDocumentCache: cache,
    serviceUrl: SERVICE_ORIGIN
  });
  return first.document.service.did === second.document.service.did && requests === 2;
}

async function evaluateOpenApiPathMatching(testCase) {
  const document = openApiDocument({
    "/v1/orders/{id}": { get: { security: [{ aep: [] }] } },
    "/v1/{kind}/123": { get: { security: [] } }
  });
  const result = interpretAepOpenApiOperation(document, {
    method: testCase.input.method,
    trailingSlash: "strict",
    url: `https://api.example.com${testCase.input.path}?${testCase.input.query}`
  });
  return result.state === "required" && result.methods.includes("aep-jwt");
}

async function evaluateOpenApiSecurity() {
  const required = interpretAepOpenApiOperation(openApiDocument({ "/items": { get: {} } }), {
    method: "GET",
    trailingSlash: "strict",
    url: "https://api.example.com/items"
  });
  const publicResult = interpretAepOpenApiOperation(
    openApiDocument({ "/items": { get: { security: [] } } }),
    {
      method: "GET",
      trailingSlash: "strict",
      url: "https://api.example.com/items"
    }
  );
  return required.state === "required" && publicResult.state === "public";
}

async function evaluateOpenApiUrlResolution(testCase) {
  let requested;
  const inspect = inspectResult({
    http: {
      endpoint_base: "/aep/",
      openapi: { path_matching: { trailing_slash: "strict" }, url: testCase.input.relative }
    }
  });
  await inspectOpenApiPolicy({
    fetch: (url) => {
      requested = String(url);
      return jsonResponse(openApiDocument({}), 200, "application/json");
    },
    inspect: { ...inspect, finalUrl: new URL(testCase.input.final_inspect_url) },
    url: "https://api.example.com/items"
  });
  return requested === testCase.expected.relative_resolved;
}

async function evaluatePlatformDiscovery(testCase) {
  const result = await withGlobalFetch(
    () => jsonResponse(testCase.expected),
    () => discoverPlatform({ platformUrl: PLATFORM_ORIGIN })
  );
  return isDeepStrictEqual(result.document, testCase.expected);
}

async function evaluatePlatformProvisionRequest(testCase) {
  let call;
  await withGlobalFetch(
    (url, init) => {
      call = { url: String(url), init };
      return jsonResponse(platformIdentity(testCase.input.service_did));
    },
    () =>
      provisionPlatformIdentity({
        discovery: platformDiscovery(),
        idempotencyKey: testCase.expected.idempotency_key_header,
        platformUrl: PLATFORM_ORIGIN,
        serviceDid: testCase.input.service_did
      })
  );
  return (
    new Headers(call.init.headers).get("idempotency-key") ===
      testCase.expected.idempotency_key_header &&
    JSON.parse(call.init.body).service_did === testCase.input.service_did
  );
}

async function evaluatePlatformProvisionResponse(testCase) {
  const result = await withGlobalFetch(
    () => jsonResponse(testCase.expected),
    () =>
      provisionPlatformIdentity({
        discovery: platformDiscovery(),
        idempotencyKey: "provision",
        platformUrl: PLATFORM_ORIGIN,
        serviceDid: testCase.expected.service_did
      })
  );
  return isDeepStrictEqual(result.body, testCase.expected);
}

async function evaluateDistinctPlatformIdentities(testCase) {
  const responses = [testCase.expected.first_response, testCase.expected.second_response];
  let index = 0;
  const results = [];
  for (const request of [testCase.input.first_request, testCase.input.second_request]) {
    results.push(
      await withGlobalFetch(
        () => jsonResponse(responses[index++]),
        () =>
          provisionPlatformIdentity({
            discovery: platformDiscovery(),
            idempotencyKey: request.idempotency_key_header,
            platformUrl: PLATFORM_ORIGIN,
            serviceDid: request.service_did
          })
      )
    );
  }
  return (
    results[0].body.agent_did !== results[1].body.agent_did &&
    results[0].body.service_did !== results[1].body.service_did
  );
}

async function evaluatePlatformList(testCase) {
  let requested;
  const result = await withGlobalFetch(
    (url) => {
      requested = new URL(url);
      return jsonResponse(testCase.expected);
    },
    () =>
      listPlatformIdentities({
        discovery: platformDiscovery(),
        platformUrl: PLATFORM_ORIGIN,
        ...camelQuery(testCase.input.query)
      })
  );
  return (
    isDeepStrictEqual(result.body, testCase.expected) &&
    requested.searchParams.get("service_did") === testCase.input.query.service_did
  );
}

async function evaluatePlatformSignRequest(testCase) {
  let call;
  const signer = createPlatformDelegatedSigner({
    discovery: platformDiscovery(),
    identity: platformIdentity(testCase.input.service_did),
    idempotencyKey: testCase.expected.idempotency_key_header,
    platformUrl: PLATFORM_ORIGIN
  });
  await withGlobalFetch(
    (_url, init) => {
      call = init;
      return jsonResponse(platformSignResponse(testCase.input));
    },
    () =>
      signer(
        buildClientAssertionClaims({
          agentDid: platformIdentity().agent_did,
          clock: () => new Date("2026-07-06T12:00:00Z"),
          command: testCase.input.op,
          jti: testCase.input.jti,
          serviceDid: testCase.input.service_did,
          ttlSeconds: Number(testCase.input.lifetime_seconds)
        }),
        {
          command: testCase.input.op,
          platformContext: testCase.input.platform_context,
          serviceDid: testCase.input.service_did,
          signingAlgorithms: ["ES256"]
        }
      )
  );
  const body = JSON.parse(call.body);
  return (
    new Headers(call.headers).get("idempotency-key") === testCase.expected.idempotency_key_header &&
    isDeepStrictEqual(body, testCase.input)
  );
}

async function evaluatePlatformSignResponse(testCase) {
  const response = testCase.expected;
  const signer = createPlatformDelegatedSigner({
    discovery: platformDiscovery(),
    identity: platformIdentity(response.service_did),
    platformUrl: PLATFORM_ORIGIN
  });
  const result = await withGlobalFetch(
    () => jsonResponse(response),
    () =>
      signer(
        buildClientAssertionClaims({
          agentDid: platformIdentity().agent_did,
          clock: () => new Date("2026-07-06T12:00:00Z"),
          command: "enroll",
          jti: response.jti ?? "jti",
          serviceDid: response.service_did ?? SERVICE_DID,
          ttlSeconds: 300
        }),
        {
          command: "enroll",
          serviceDid: response.service_did ?? SERVICE_DID,
          signingAlgorithms: ["ES256"]
        }
      )
  );
  return isDeepStrictEqual(result, camelSignResult(response));
}

async function evaluatePlatformConflict(testCase) {
  try {
    await withGlobalFetch(
      () =>
        jsonResponse(
          {
            type: "urn:aep:error:idempotency_conflict",
            title: "Idempotency conflict",
            status: 409,
            code: "idempotency_conflict"
          },
          409,
          "application/problem+json"
        ),
      () =>
        provisionPlatformIdentity({
          discovery: platformDiscovery(),
          idempotencyKey: testCase.input.initial_sign_key,
          platformUrl: PLATFORM_ORIGIN,
          serviceDid: SERVICE_DID
        })
    );
    return false;
  } catch (error) {
    return (
      error instanceof AepCommandError &&
      error.status === testCase.expected.changed_input_or_operation_status &&
      error.problem?.code === testCase.expected.changed_input_or_operation_code
    );
  }
}

async function evaluateCredentialPresentations() {
  const oauth = credentialPresentationHeaders(grantResponse("oauth-bearer"));
  const apiKey = credentialPresentationHeaders(grantResponse("api-key"));
  const basic = credentialPresentationHeaders(grantResponse("basic"));
  return (
    oauth.Authorization?.startsWith("Bearer ") &&
    apiKey["x-api-key"] === "opaque-api-key" &&
    basic.Authorization?.startsWith("Basic ")
  );
}

async function evaluateAuthenticateAssertion(testCase) {
  let claims;
  const headers = await clientAssertionAuthenticationHeaders({
    agentDid: testCase.expected.claims.iss,
    clock: () => new Date(testCase.expected.claims.iat * 1000),
    command: "authenticate",
    jti: testCase.expected.claims.jti,
    resource: testCase.input.url,
    serviceDid: testCase.expected.claims.aud,
    signer: (value) => {
      claims = value;
      return "compact-jws";
    },
    ttlSeconds: testCase.expected.claims.exp - testCase.expected.claims.iat
  });
  return (
    headers.Authorization === "AEP compact-jws" &&
    isDeepStrictEqual(claims, testCase.expected.claims)
  );
}

async function evaluateAuthorizationCarriers() {
  const jwtStandard = await clientAssertionAuthenticationHeaders({
    agentDid: AGENT_DID,
    carrier: "standard",
    serviceDid: SERVICE_DID,
    signer: () => "compact-jws"
  });
  const jwtDedicated = await clientAssertionAuthenticationHeaders({
    agentDid: AGENT_DID,
    carrier: "dedicated",
    serviceDid: SERVICE_DID,
    signer: () => "compact-jws"
  });
  const bearerStandard = credentialPresentationHeaders(grantResponse("oauth-bearer"), "standard");
  const bearerDedicated = credentialPresentationHeaders(grantResponse("oauth-bearer"), "dedicated");
  const basicStandard = credentialPresentationHeaders(grantResponse("basic"), "standard");
  const basicDedicated = credentialPresentationHeaders(grantResponse("basic"), "dedicated");
  return (
    jwtStandard.Authorization === "AEP compact-jws" &&
    jwtDedicated["AEP-Authorization"] === "AEP compact-jws" &&
    bearerStandard.Authorization?.startsWith("Bearer ") &&
    bearerDedicated["AEP-Authorization"]?.startsWith("Bearer ") &&
    basicStandard.Authorization?.startsWith("Basic ") &&
    basicDedicated["AEP-Authorization"]?.startsWith("Basic ")
  );
}

async function evaluatePaymentComposition() {
  const mpp = {
    ...(await clientAssertionAuthenticationHeaders({
      agentDid: AGENT_DID,
      carrier: "dedicated",
      serviceDid: SERVICE_DID,
      signer: () => "compact-jws"
    })),
    Authorization: "Payment mpp-credential"
  };
  const x402 = {
    ...credentialPresentationHeaders(grantResponse("oauth-bearer"), "dedicated"),
    "PAYMENT-SIGNATURE": "x402-signature"
  };
  return (
    mpp.Authorization.startsWith("Payment ") &&
    mpp["AEP-Authorization"].startsWith("AEP ") &&
    x402["AEP-Authorization"].startsWith("Bearer ") &&
    x402["PAYMENT-SIGNATURE"] === "x402-signature"
  );
}

function evaluateApiKeyHeader(testCase) {
  const headers = credentialPresentationHeaders({
    ...grantResponse("api-key"),
    api_key: testCase.input.api_key,
    header: testCase.input.issued_header
  });
  return (
    headers[testCase.input.issued_header] === testCase.input.api_key &&
    headers[testCase.input.presented_header] === undefined
  );
}

async function evaluateAuthenticationMethods(testCase) {
  for (const value of Object.values(testCase.expected).filter((item) => typeof item === "object")) {
    const result = await inspectWithDocument({
      ...baseInspectDocument(),
      authentication: value.authentication
    });
    if (!isDeepStrictEqual(result.document.authentication, value.authentication)) return false;
  }
  const omitted = await inspectWithDocument({
    ...baseInspectDocument(),
    authentication: undefined
  });
  return omitted.document.authentication === undefined;
}

function evaluateOperationBinding(testCase) {
  const resource = buildClientAssertionClaims({
    agentDid: AGENT_DID,
    command: "authenticate",
    resource: testCase.input.protected_resource,
    serviceDid: SERVICE_DID
  });
  return (
    testCase.input.command_endpoints.every(
      (command) =>
        buildClientAssertionClaims({ agentDid: AGENT_DID, command, serviceDid: SERVICE_DID }).op ===
        command
    ) &&
    resource.op === "authenticate" &&
    resource.resource === testCase.input.protected_resource
  );
}

async function evaluateProtectedResourceSafety(id) {
  if (id === "authorization-field-safety") {
    const headers = await clientAssertionAuthenticationHeaders({
      agentDid: AGENT_DID,
      carrier: "dedicated",
      serviceDid: SERVICE_DID,
      signer: () => "compact-jws"
    });
    return (
      headers["AEP-Authorization"] === "AEP compact-jws" && headers.Authorization === undefined
    );
  }
  if (id === "redirect-safety") {
    let authenticationCalls = 0;
    const agent = {
      serviceSession: () => ({
        authenticationHeaders: async () => {
          authenticationCalls += 1;
          return { Authorization: "AEP signed" };
        },
        openApiPolicy: async () => ({
          source: "openapi",
          state: "fallback",
          methods: [],
          freshness: "fetched"
        }),
        inspect: async () => inspectResult()
      })
    };
    let call = 0;
    const response = await fetchProtectedResource({
      agent,
      fetch: (url, init) => {
        call += 1;
        const authenticated = new Headers(init?.headers).has("authorization");
        if (!authenticated) {
          return Promise.resolve(
            new Response(null, {
              status: 401,
              headers: {
                "www-authenticate": `AEP service_did="${SERVICE_DID}", inspect="${SERVICE_ORIGIN}/.well-known/aep"`
              }
            })
          );
        }
        if (new URL(url).pathname.endsWith("/123")) {
          return Promise.resolve(
            new Response(null, { status: 302, headers: { location: "/v1/orders/124" } })
          );
        }
        return Promise.resolve(new Response("ok", { status: 200 }));
      },
      url: "https://api.example.com/v1/orders/123"
    });
    return response.status === 200 && authenticationCalls === 2 && call === 4;
  }
  if (id === "assertion-and-credential-failures") {
    const headers = await protectedResourceAuthenticationHeaders({
      credential: grantResponse("oauth-bearer")
    });
    return headers.Authorization?.startsWith("Bearer ") === true;
  }
  const dedicated = await clientAssertionAuthenticationHeaders({
    agentDid: AGENT_DID,
    carrier: "dedicated",
    serviceDid: SERVICE_DID,
    signer: () => "signed"
  });
  const standard = credentialPresentationHeaders(grantResponse("oauth-bearer"));
  return dedicated["AEP-Authorization"] !== undefined && standard.Authorization !== undefined;
}

async function captureCommand(operation, responseBody = { status: "active" }) {
  let call;
  await withGlobalFetch((input, init) => {
    call = { input: String(input), init };
    return jsonResponse(responseBody);
  }, operation);
  return call;
}

function requestMatches(call, expected, assertion) {
  const headers = new Headers(call.init.headers);
  const body = call.init.body === undefined ? undefined : JSON.parse(call.init.body);
  return (
    call.init.method === expected.method &&
    new URL(call.input).pathname === expected.path &&
    headers.get("content-type") === expected.content_type &&
    headers.get("authorization") === `${expected.authorization_scheme} ${assertion}` &&
    (expected.idempotency_key === undefined ||
      headers.get("idempotency-key") === expected.idempotency_key) &&
    isDeepStrictEqual(body, expected.body ?? body) &&
    (expected.must_not_contain ?? []).every((field) => body[field] === undefined)
  );
}

async function inspectWithDocument(document) {
  return inspectService({ fetch: () => jsonResponse(document), serviceUrl: SERVICE_ORIGIN });
}

function inspectResult(overrides = {}) {
  const document = mergeInspect(baseInspectDocument(), overrides);
  return {
    commandUrl: (command) =>
      new URL(`${document.http.endpoint_base ?? "/aep/"}${command}`, SERVICE_ORIGIN),
    document,
    finalUrl: new URL(`${SERVICE_ORIGIN}/.well-known/aep`),
    inspectUrl: new URL(`${SERVICE_ORIGIN}/.well-known/aep`)
  };
}

function mergeInspect(document, overrides) {
  return {
    ...document,
    ...overrides,
    commands: { ...document.commands, ...(overrides.commands ?? {}) },
    core: { ...document.core, ...(overrides.core ?? {}) },
    http: { ...document.http, ...(overrides.http ?? {}) },
    identity: { ...document.identity, ...(overrides.identity ?? {}) },
    service: { ...document.service, ...(overrides.service ?? {}) }
  };
}

function baseInspectDocument() {
  return {
    aep_version: "1.0",
    authentication: { methods: ["aep-jwt", "oauth-bearer", "api-key", "basic"] },
    bindings: { supported: ["http"] },
    claims: { optional: [], preferred: [], required: [] },
    commands: {
      grant_types: ["oauth-bearer", "api-key", "basic"],
      supported: ["enroll", "grant", "inspect", "revoke", "status"]
    },
    core: { signing_algorithms: ["EdDSA", "ES256"] },
    extensions: { supported: [] },
    http: { endpoint_base: "/aep/" },
    identity: { methods: ["did:web"] },
    service: { did: SERVICE_DID }
  };
}

function platformDiscovery() {
  const document = platformDiscoveryDocument();
  return {
    discoveryUrl: new URL(`${PLATFORM_ORIGIN}/.well-known/aep-platform`),
    document,
    endpointUrl: (endpoint) => new URL(document.endpoints[endpoint], PLATFORM_ORIGIN)
  };
}

function platformDiscoveryDocument() {
  return {
    aep_version: "1.0",
    endpoints: {
      hosted_verification: "/v1/aep/verifications",
      lifecycle: "/v1/aep/agent-identities/{agent_identity_id}",
      list: "/v1/aep/agent-identities",
      provision: "/v1/aep/agent-identities",
      sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"
    },
    http: { endpoint_base: "/v1/aep" },
    identity: {
      did_methods: ["did:web"],
      did_url_template: `${PLATFORM_ORIGIN}/a/{agent_did_id}/did.json`
    },
    platform: { did: "did:web:p.example", hosted_verification: true, name: "Example Platform" },
    signing: { algorithms: ["ES256"], default_lifetime_seconds: "300" }
  };
}

function platformIdentity(serviceDid = SERVICE_DID) {
  return {
    agent_did: "did:web:p.example:a:4Yf7p2xQd9",
    agent_identity_id: "pai_01J0AEPPLATFORM000000000001",
    created_at: "2026-07-06T12:00:00Z",
    did_document_url: `${PLATFORM_ORIGIN}/a/4Yf7p2xQd9/did.json`,
    key_id: "did:web:p.example:a:4Yf7p2xQd9",
    service_did: serviceDid,
    signing_algorithms: ["ES256"],
    status: "active",
    updated_at: "2026-07-06T12:00:00Z"
  };
}

function platformSignResponse(input) {
  return {
    status: "completed",
    agent_did: platformIdentity().agent_did,
    client_assertion: "signed.jwt",
    expires_at: "2026-07-06T12:05:00Z",
    issued_at: "2026-07-06T12:00:00Z",
    jti: input.jti,
    platform_context: input.platform_context,
    service_did: input.service_did
  };
}

function camelSignResult(value) {
  return {
    status: value.status,
    ...(value.client_assertion === undefined ? {} : { clientAssertion: value.client_assertion }),
    ...(value.platform_context === undefined ? {} : { platformContext: value.platform_context }),
    ...(value.retry_after_seconds === undefined
      ? {}
      : { retryAfterSeconds: Number(value.retry_after_seconds) })
  };
}

function camelQuery(value) {
  return {
    descending: value.descending,
    limit: value.limit,
    offset: value.offset,
    serviceDid: value.service_did,
    status: value.status
  };
}

function openApiDocument(paths) {
  return {
    openapi: "3.1.0",
    components: {
      securitySchemes: {
        aep: { type: "http", scheme: "AEP", "x-aep-authentication-method": "aep-jwt" }
      }
    },
    security: [{ aep: [] }],
    paths
  };
}

function grantResponse(grantType) {
  if (grantType === "api-key")
    return {
      api_key: "opaque-api-key",
      credential_id: "key-1",
      expires_at: "2999-01-01T00:00:00Z",
      header: "x-api-key",
      scopes: []
    };
  if (grantType === "basic")
    return {
      credential_id: "basic-1",
      expires_at: "2999-01-01T00:00:00Z",
      password: "password",
      scopes: [],
      username: "user"
    };
  return {
    access_token: "opaque-token",
    credential_id: "oauth-1",
    expires_at: "2999-01-01T00:00:00Z",
    scopes: ["read"],
    token_type: "Bearer"
  };
}

function responseFromExpectation(expected) {
  return jsonResponse(expected.body, expected.status, expected.content_type);
}

function jsonResponse(value, status = 200, contentType = "application/aep+json", options = {}) {
  return Promise.resolve(
    new Response(JSON.stringify(value), {
      status,
      headers: { "content-type": contentType, ...(options.headers ?? {}) }
    })
  );
}

async function withGlobalFetch(fetch, operation) {
  const original = globalThis.fetch;
  globalThis.fetch = fetch;
  try {
    return await operation();
  } finally {
    globalThis.fetch = original;
  }
}
