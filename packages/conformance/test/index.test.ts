import {
  AEP_CLAIM_NAMES,
  claimValuesSchema,
  evaluateAepClaimSupport,
  inspectDocumentSchema,
  isAepVersionCompatible,
  validateAepClaimValues
} from "@aep-foundation/core";
import type { InspectDocument } from "@aep-foundation/core";
import {
  apiKeyGrantType,
  basicGrantType,
  buildInspectDocument,
  createInMemoryCommandIdempotencyStore,
  createInMemoryEnrollmentStore,
  createStaticEnrollmentPolicy,
  didWebIdentityMethod,
  handleEnrollRequest,
  handleGrantRequest,
  handleRevokeRequest,
  handleStatusRequest,
  oauthBearerGrantType
} from "@aep-foundation/service";
import { describe, expect, it } from "vitest";

import {
  AepConformanceError,
  assertBuiltInGrantResponseConformance,
  assertClaimValuesConformance,
  assertEnrollRequestConformance,
  assertEnrollResponseConformance,
  assertGrantRequestConformance,
  assertInspectConformance,
  assertProblemDetailsConformance,
  assertRevokeRequestConformance,
  assertRevokeResponseConformance,
  assertStatusResponseConformance,
  loadAllGrantTypesRevokeRequestTestVector,
  loadActiveEnrollResponseTestVector,
  loadActiveStatusResponseTestVector,
  loadApiKeyGrantResponseTestVector,
  loadBasicGrantResponseTestVector,
  loadClaimsCatalogEnrollRequestTestVector,
  loadClaimsCatalogInspectTestVector,
  loadClaimNegotiationCompatibilityTestVector,
  loadClaimValueValidationTestVector,
  loadClaimValuesTestVector,
  loadCommandIdempotencyHeaderTestVector,
  loadCommandReplayConflictTestVector,
  loadEmptyRevokeResponseTestVector,
  loadExampleArtifact,
  loadEnrollIdempotencyConflictTestVector,
  loadMinimalInspectTestVector,
  loadMinimalEnrollRequestTestVector,
  loadNotRecognizedProblemTestVector,
  loadOAuthBearerGrantRequestTestVector,
  loadOAuthBearerGrantResponseTestVector,
  loadOAuthBearerRevokeRequestTestVector,
  loadPlatformDiscoveryTestVector,
  loadPlatformLifecycleRequestTestVector,
  loadPlatformListResponseTestVector,
  loadPlatformProvisionRequestTestVector,
  loadPlatformSignRequestTestVector,
  loadPlatformVerificationResponseRecognizedTestVector,
  loadPlatformVerificationResponseUnrecognizedTestVector,
  loadRegistryArtifact,
  loadSchemaArtifact,
  loadSpecArtifactManifest,
  loadTestVector,
  loadUnknownRequiredClaimTestVector,
  schemaArtifactPath,
  schemaArtifactsRoot,
  specArtifactsRoot,
  testVectorArtifactPath,
  testVectorArtifactsRoot,
  validateEnrollRequestConformance,
  validateEnrollResponseConformance,
  validateGrantRequestConformance,
  validateInspectConformance,
  validateClaimValuesConformance,
  validateProblemDetailsConformance
} from "../src/index.js";

describe("@aep-foundation/conformance spec artifacts", () => {
  it("exposes stable fixture paths", () => {
    expect(specArtifactsRoot).toContain("fixtures/aep-specs");
    expect(schemaArtifactsRoot).toContain("fixtures/aep-specs/schemas");
    expect(testVectorArtifactsRoot).toContain("fixtures/aep-specs/test-vectors");
    expect(schemaArtifactPath("inspect-document.schema.json")).toContain(
      "fixtures/aep-specs/schemas/inspect-document.schema.json"
    );
    expect(testVectorArtifactPath("inspect/minimal-http.json")).toContain(
      "fixtures/aep-specs/test-vectors/inspect/minimal-http.json"
    );
  });

  it("loads the synced artifact manifest", async () => {
    const manifest = await loadSpecArtifactManifest();

    expect(manifest.source_repository).toBe("https://github.com/aep-foundation/aep-specs");
    expect(manifest.source_revision).toMatch(/^[0-9a-f]{40}$/);
    expect(manifest.source_directory).toBe("ietf");
    expect(manifest.source).toBe(
      `${manifest.source_repository}/tree/${manifest.source_revision}/${manifest.source_directory}`
    );
    expect(manifest.artifact_revision).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(manifest.generated_by).toBe("scripts/sync-aep-spec-artifacts.mjs");
    expect(manifest.artifacts.schemas).toContain("inspect-document.schema.json");
    expect(manifest.artifacts.examples).toContain("authorization-composition.md");
    expect(manifest.artifacts.registry).toContain("http-fields/aep-authorization.json");
    expect(manifest.artifacts.registry).toContain("claim-names/contact.email.json");
    expect(manifest.artifacts.schemas).toContain("claim-values.schema.json");
    expect(manifest.artifacts["test-vectors"]).toContain("claims/person-contact-catalog.json");
    expect(manifest.artifacts["test-vectors"]).toContain("inspect/minimal-http.json");
    expect(manifest.artifacts["test-vectors"]).toContain("enroll/request-minimal.json");
    expect(manifest.artifacts["test-vectors"]).toContain("status/response-active.json");
    expect(manifest.artifacts["test-vectors"]).toContain(
      "grant-revoke/grant-request-oauth-bearer.json"
    );
    expect(manifest.artifacts["test-vectors"]).toContain(
      "credentials/oauth-bearer/grant-response.json"
    );
    expect(manifest.artifacts["test-vectors"]).toContain("errors/not-recognized-problem.json");
    expect(manifest.artifacts["test-vectors"]).toContain("idempotency/enroll-conflict.json");
    expect(manifest.artifacts["test-vectors"]).toContain("idempotency/command-header.json");
    expect(manifest.artifacts["test-vectors"]).toContain(
      "idempotency/command-replay-conflict.json"
    );
    expect(manifest.artifacts["test-vectors"]).toContain("index.json");
    expect(manifest.artifacts.schemas).toContain("platform-discovery.schema.json");
    expect(manifest.artifacts.schemas).toContain("platform-provision-request.schema.json");
    expect(manifest.artifacts["test-vectors"]).toContain("platform/discovery.json");
    expect(manifest.artifacts["test-vectors"]).toContain("platform/provision-request.json");
    expect(manifest.artifacts["test-vectors"]).toContain(
      "platform/verification-response-recognized.json"
    );
  });

  it("loads the finalized dedicated-field registry and example artifacts", async () => {
    await expect(
      loadRegistryArtifact<{ wire_identifier: string }>("http-fields/aep-authorization.json")
    ).resolves.toMatchObject({ wire_identifier: "aep-authorization" });
    await expect(loadExampleArtifact("authorization-composition.md")).resolves.toContain(
      "AEP-Authorization"
    );
  });

  it("loads schemas and test vectors by relative artifact path", async () => {
    const schema = await loadSchemaArtifact<{ title: string }>("inspect-document.schema.json");
    const vector = await loadTestVector<Record<string, never>, unknown>(
      "inspect/minimal-http.json"
    );

    expect(schema.title).toBe("AEP Inspect Document");
    expect(vector.id).toBe("minimal-http");
    expect(vector.applicability.agent).toEqual({
      expectation: "required",
      profile: "core-http"
    });
    expect(vector.applicability.platform).toEqual({ expectation: "unsupported" });
  });
});

describe("@aep-foundation/conformance Claims checks", () => {
  it("validates the synced claim catalog vector", async () => {
    const vector = await loadClaimValuesTestVector();

    expect(vector.id).toBe("person-contact-catalog");
    expect(validateClaimValuesConformance(vector.expected).ok).toBe(true);
    expect(assertClaimValuesConformance(vector.expected)).toEqual(vector.expected);
  });

  it("keeps runtime schema metadata identical to the synced schema", async () => {
    await expect(loadSchemaArtifact("claim-values.schema.json")).resolves.toEqual(
      claimValuesSchema
    );
  });

  it("enforces every synced positive and negative Claim Value vector", async () => {
    const ids = [
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
    ] as const;

    for (const id of ids) {
      const vector = await loadClaimValueValidationTestVector(id);
      expect(validateAepClaimValues(vector.input.claim_values).ok, id).toBe(vector.expected.valid);
    }
  });

  it("enforces the synced forward-compatibility negotiation vectors", async () => {
    const compatibility = await loadClaimNegotiationCompatibilityTestVector();
    const unknownRequired = await loadUnknownRequiredClaimTestVector();

    expect(
      evaluateAepClaimSupport(
        {
          optional: compatibility.input.inspect.optional,
          preferred: compatibility.input.inspect.preferred,
          required: compatibility.input.inspect.required
        },
        AEP_CLAIM_NAMES
      )
    ).toMatchObject({
      canSatisfyRequired: true,
      supportedOptional: [],
      supportedPreferred: []
    });
    expect(
      evaluateAepClaimSupport(
        { required: unknownRequired.input.required },
        unknownRequired.input.understood
      ).canSatisfyRequired
    ).toBe(unknownRequired.expected.can_satisfy);
  });

  it("validates synced claim catalog Inspect and Enroll vectors", async () => {
    const inspect = await loadClaimsCatalogInspectTestVector();
    const enroll = await loadClaimsCatalogEnrollRequestTestVector();

    expect(inspect.expected.claims).toEqual({
      optional: ["person.username"],
      preferred: ["contact.mobile", "contact.address.primary", "person.birthdate"],
      required: ["contact.email", "person.first_name", "person.last_name"]
    });
    expect(validateInspectConformance(inspect.expected).ok).toBe(true);
    expect(validateEnrollRequestConformance(enroll.input).ok).toBe(true);
    expect(assertClaimValuesConformance(enroll.input.claims)).toEqual(enroll.input.claims);
  });

  it("loads claim-name registry metadata", async () => {
    await expect(
      loadRegistryArtifact<{ value_type: string; wire_identifier: string }>(
        "claim-names/contact.email.json"
      )
    ).resolves.toMatchObject({
      value_type: "string",
      wire_identifier: "contact.email"
    });
  });
});

describe("@aep-foundation/conformance Platform checks", () => {
  it("loads Platform Hosted Identity vectors by stable helper", async () => {
    const discovery = await loadPlatformDiscoveryTestVector();
    const provision = await loadPlatformProvisionRequestTestVector();
    const list = await loadPlatformListResponseTestVector();
    const lifecycle = await loadPlatformLifecycleRequestTestVector();
    const sign = await loadPlatformSignRequestTestVector();
    const recognized = await loadPlatformVerificationResponseRecognizedTestVector();
    const unrecognized = await loadPlatformVerificationResponseUnrecognizedTestVector();

    expect(discovery.expected).toMatchObject({
      platform: {
        did: "did:web:p.example",
        hosted_verification: true
      }
    });
    expect(provision.input).toEqual({
      service_did: "did:web:api.service.example"
    });
    expect(list.expected).toMatchObject({
      count: "1",
      total: "1"
    });
    expect(lifecycle.input).toEqual({
      status: "suspended"
    });
    expect(sign.input).toMatchObject({
      lifetime_seconds: "300",
      op: "enroll"
    });
    expect(recognized.expected).toMatchObject({
      reason: "verified",
      verified: true
    });
    expect(unrecognized.expected).toMatchObject({
      reason: "not_recognized",
      verified: false
    });
  });
});

describe("@aep-foundation/conformance error and idempotency checks", () => {
  it("loads the Core command idempotency vectors", async () => {
    const header = await loadCommandIdempotencyHeaderTestVector();
    const replay = await loadCommandReplayConflictTestVector();

    expect(header.input.commands).toEqual(["enroll", "grant", "revoke"]);
    expect(header.expected).toMatchObject({
      enroll_body_key: "optional",
      header_required: true,
      missing_or_empty_code: "invalid_request"
    });
    expect(replay.input).toMatchObject({
      first_command: "grant",
      second_command: "revoke"
    });
    expect(replay.expected).toMatchObject({
      retention_seconds_minimum: 3600,
      scope: ["agent_did", "idempotency_key"]
    });
  });

  it("validates the synced not_recognized Problem Details vector", async () => {
    const vector = await loadNotRecognizedProblemTestVector();

    expect(vector.id).toBe("not-recognized-problem");
    expect(validateProblemDetailsConformance(vector.expected.body).ok).toBe(true);
    expect(assertProblemDetailsConformance(vector.expected.body)).toEqual({
      code: "not_recognized",
      status: 401,
      title: "Not recognized",
      type: "urn:aep:error:not_recognized"
    });
    expect(vector.expected).toMatchObject({
      content_type: "application/problem+json",
      status: 401
    });
  });

  it("validates the synced Enroll idempotency conflict vector", async () => {
    const vector = await loadEnrollIdempotencyConflictTestVector();

    expect(vector.id).toBe("enroll-conflict");
    expect(vector.input).toMatchObject({
      first_body_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      second_body_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    });
    expect(assertProblemDetailsConformance(vector.expected.body)).toEqual({
      code: "idempotency_conflict",
      status: 409,
      title: "Idempotency conflict",
      type: "urn:aep:error:idempotency_conflict"
    });
    expect(vector.expected).toMatchObject({
      content_type: "application/problem+json",
      status: 409
    });
  });

  it("compares @aep-foundation/service not_recognized output against the synced error vector", async () => {
    const vector = await loadNotRecognizedProblemTestVector();
    const response = await handleStatusRequest("did:web:agent.example.com:agents:missing", {
      store: createInMemoryEnrollmentStore()
    });

    expect(response).toEqual({
      body: vector.expected.body,
      contentType: vector.expected.content_type,
      headers: { "WWW-Authenticate": 'AEP reason="not_recognized"' },
      status: vector.expected.status
    });
  });

  it("compares @aep-foundation/service Enroll idempotency conflict output against the synced vector", async () => {
    const vector = await loadEnrollIdempotencyConflictTestVector();
    const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
    const store = createInMemoryEnrollmentStore();
    const options = {
      commandIdempotencyStore,
      idempotencyKey: vector.input.idempotency_key,
      policy: createStaticEnrollmentPolicy(),
      store
    };

    await handleEnrollRequest(
      {
        agent_did: vector.input.agent_did,
        idempotency_key: vector.input.idempotency_key
      },
      options
    );

    const response = await handleEnrollRequest(
      {
        agent_did: vector.input.agent_did,
        claims: {
          "contact.email": "different@example.com"
        },
        idempotency_key: vector.input.idempotency_key
      },
      options
    );

    expect(response).toEqual({
      body: vector.expected.body,
      contentType: vector.expected.content_type,
      status: vector.expected.status
    });
  });
});

describe("@aep-foundation/conformance Enroll and Status checks", () => {
  it("validates the synced minimal Enroll request vector", async () => {
    const vector = await loadMinimalEnrollRequestTestVector();

    expect(vector.id).toBe("request-minimal");
    expect(validateEnrollRequestConformance(vector.input).ok).toBe(true);
    expect(assertEnrollRequestConformance(vector.input)).toEqual(vector.input);
    expect(vector.expected).toMatchObject({
      authorization_scheme: "AEP",
      client_assertion_op: "enroll",
      content_type: "application/aep+json",
      method: "POST",
      path: "/aep/enroll"
    });
  });

  it("validates the synced active Enroll response vector", async () => {
    const vector = await loadActiveEnrollResponseTestVector();

    expect(vector.id).toBe("response-active");
    expect(validateEnrollResponseConformance(vector.expected.body).ok).toBe(true);
    expect(assertEnrollResponseConformance(vector.expected.body)).toEqual({
      status: "active"
    });
  });

  it("validates the synced active Status response vector", async () => {
    const vector = await loadActiveStatusResponseTestVector();

    expect(vector.id).toBe("response-active");
    expect(assertStatusResponseConformance(vector.expected.body)).toEqual({
      since: "2026-05-28T12:00:00Z",
      status: "active"
    });
  });

  it("compares @aep-foundation/service Enroll output against the synced active response vector", async () => {
    const vector = await loadActiveEnrollResponseTestVector();
    const store = createInMemoryEnrollmentStore();
    const response = await handleEnrollRequest(
      {
        agent_did: "did:web:agent.example.com:agents:123",
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      },
      {
        clock: () => new Date("2026-05-28T12:00:00.000Z"),
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
        policy: createStaticEnrollmentPolicy(),
        store
      }
    );

    expect(response).toEqual({
      body: vector.expected.body,
      contentType: vector.expected.content_type,
      status: vector.expected.status
    });
  });

  it("compares @aep-foundation/service Status output against the synced active response vector", async () => {
    const vector = await loadActiveStatusResponseTestVector();
    const store = createInMemoryEnrollmentStore();

    await handleEnrollRequest(
      {
        agent_did: "did:web:agent.example.com:agents:123",
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      },
      {
        clock: () => new Date("2026-05-28T12:00:00.000Z"),
        idempotencyKey: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
        policy: createStaticEnrollmentPolicy(),
        store
      }
    );

    const response = await handleStatusRequest("did:web:agent.example.com:agents:123", { store });

    expect(response).toEqual({
      body: {
        ...vector.expected.body,
        since: "2026-05-28T12:00:00.000Z"
      },
      contentType: vector.expected.content_type,
      status: vector.expected.status
    });
  });

  it("throws AepConformanceError with validation issues for invalid Enroll output", () => {
    expect(() =>
      assertEnrollResponseConformance({
        status: "unknown"
      })
    ).toThrow(AepConformanceError);
  });
});

describe("@aep-foundation/conformance Grant, Revoke, and credential checks", () => {
  it("validates the synced Grant and Revoke request vectors", async () => {
    const grant = await loadOAuthBearerGrantRequestTestVector();
    const revoke = await loadOAuthBearerRevokeRequestTestVector();
    const revokeAll = await loadAllGrantTypesRevokeRequestTestVector();

    expect(grant.id).toBe("grant-request-oauth-bearer");
    expect(validateGrantRequestConformance(grant.input).ok).toBe(true);
    expect(assertGrantRequestConformance(grant.input)).toEqual({
      grant_type: "oauth-bearer"
    });
    expect(grant.expected).toMatchObject({
      authorization_scheme: "AEP",
      client_assertion_op: "grant",
      content_type: "application/aep+json",
      method: "POST",
      path: "/aep/grant"
    });

    expect(assertRevokeRequestConformance(revoke.input)).toEqual({
      grant_type: "oauth-bearer"
    });
    expect(assertRevokeRequestConformance(revokeAll.input)).toEqual({
      all_grant_types: "true"
    });
    expect(revokeAll.expected.must_not_contain).toEqual(["grant_type", "credential_id"]);
  });

  it("validates synced built-in credential response vectors", async () => {
    const oauth = await loadOAuthBearerGrantResponseTestVector();
    const apiKey = await loadApiKeyGrantResponseTestVector();
    const basic = await loadBasicGrantResponseTestVector();

    expect(assertBuiltInGrantResponseConformance("oauth-bearer", oauth.expected)).toEqual(
      oauth.expected
    );
    expect(assertBuiltInGrantResponseConformance("api-key", apiKey.expected)).toEqual(
      apiKey.expected
    );
    expect(assertBuiltInGrantResponseConformance("basic", basic.expected)).toEqual(basic.expected);
  });

  it("validates the synced empty Revoke response vector", async () => {
    const vector = await loadEmptyRevokeResponseTestVector();

    expect(vector.id).toBe("revoke-response-empty");
    expect(assertRevokeResponseConformance(vector.expected.body)).toEqual({});
  });

  it("compares @aep-foundation/service Grant output against the synced OAuth Bearer vector", async () => {
    const vector = await loadOAuthBearerGrantResponseTestVector();
    const store = createInMemoryEnrollmentStore([activeEnrollment()]);
    const response = await handleGrantRequest(vector.input, {
      agentDid: "did:web:agent.example.com:agents:123",
      handlers: new Map([
        [
          "oauth-bearer",
          {
            grant: () => vector.expected,
            revoke: () => undefined
          }
        ]
      ]),
      idempotencyKey: "grant-conformance",
      store
    });

    expect(response).toEqual({
      body: vector.expected,
      contentType: "application/aep+json",
      status: 200
    });
  });

  it("compares @aep-foundation/service Revoke output against the synced empty response vector", async () => {
    const request = await loadOAuthBearerRevokeRequestTestVector();
    const responseVector = await loadEmptyRevokeResponseTestVector();
    const store = createInMemoryEnrollmentStore([activeEnrollment()]);
    const response = await handleRevokeRequest(request.input, {
      agentDid: "did:web:agent.example.com:agents:123",
      handlers: new Map([
        [
          "oauth-bearer",
          {
            grant: () => ({}),
            revoke: () => undefined
          }
        ]
      ]),
      idempotencyKey: "revoke-conformance",
      store
    });

    expect(response).toEqual({
      body: responseVector.expected.body,
      contentType: responseVector.expected.content_type,
      status: responseVector.expected.status
    });
  });

  it("throws AepConformanceError with validation issues for invalid Grant output", () => {
    expect(() =>
      assertBuiltInGrantResponseConformance("oauth-bearer", {
        token_type: "Bearer"
      })
    ).toThrow(AepConformanceError);
  });
});

describe("@aep-foundation/conformance Inspect checks", () => {
  it("keeps runtime Inspect schema metadata identical to the synced schema", async () => {
    await expect(loadSchemaArtifact("inspect-document.schema.json")).resolves.toEqual(
      inspectDocumentSchema
    );
  });

  it("validates the synced minimal Inspect test vector", async () => {
    const vector = await loadMinimalInspectTestVector();

    expect(vector.id).toBe("minimal-http");
    expect(vector.expected.service.did).toBe("did:web:api.example.com");
    expect(validateInspectConformance(vector.expected).ok).toBe(true);
    expect(assertInspectConformance(vector.expected)).toEqual(vector.expected);
  });

  it("enforces the corrected Inspect omission and command relationships", async () => {
    const defaultEndpoint = await loadTestVector<
      Record<string, never>,
      { document: InspectDocument; endpoint_base: string; valid: boolean }
    >("inspect/default-endpoint-base.json");
    const missingGrantTypes = await loadTestVector<
      { document: Record<string, unknown> },
      { valid: boolean }
    >("inspect/grant-without-grant-types.json");

    expect(validateInspectConformance(defaultEndpoint.expected.document).ok).toBe(true);
    expect(validateInspectConformance(missingGrantTypes.input.document).ok).toBe(false);
  });

  it("executes the corrected Inspect validation vectors", async () => {
    const invalidVectorNames = [
      "authenticated-command-without-identity-method",
      "authentication-method-limit",
      "command-without-inspect",
      "grant-without-grant-types",
      "invalid-advertisement-identifiers",
      "invalid-openapi-reference",
      "missing-signing-algorithm"
    ];
    for (const name of invalidVectorNames) {
      const vector = await loadTestVector<
        { document: Record<string, unknown> },
        { valid: boolean }
      >(`inspect/${name}.json`);
      expect(vector.expected.valid, name).toBe(false);
      expect(validateInspectConformance(vector.input.document).ok, name).toBe(false);
    }

    const forwardCompatible = await loadTestVector<
      { document: Record<string, unknown> },
      { valid: boolean }
    >("inspect/forward-compatible-advertisements.json");
    expect(forwardCompatible.expected.valid).toBe(true);
    expect(validateInspectConformance(forwardCompatible.input.document).ok).toBe(true);
  });

  it("executes the protocol-version compatibility vector", async () => {
    const vector = await loadTestVector<
      { supported: string },
      {
        cases: Array<{
          compatible: boolean;
          received: string;
          supported?: string;
          valid: boolean;
        }>;
      }
    >("inspect/protocol-version.json");

    for (const testCase of vector.expected.cases) {
      expect(
        isAepVersionCompatible(testCase.received, testCase.supported ?? vector.input.supported)
      ).toBe(testCase.compatible && testCase.valid);
    }
  });

  it("compares @aep-foundation/service Inspect output against the synced minimal vector", async () => {
    const vector = await loadMinimalInspectTestVector();
    const document = buildInspectDocument({
      authenticationMethods: ["aep-jwt", "oauth-bearer", "api-key", "basic"],
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()],
      grantTypes: [oauthBearerGrantType(), apiKeyGrantType(), basicGrantType()],
      claims: {
        required: ["contact.email"]
      },
      openapi: { url: "/openapi.json", pathMatching: { trailingSlash: "strict" } }
    });

    expect(assertInspectConformance(document)).toEqual(vector.expected);
  });

  it("throws AepConformanceError with validation issues for invalid Inspect output", () => {
    expect(() =>
      assertInspectConformance({
        aep_version: "invalid"
      })
    ).toThrow(AepConformanceError);

    try {
      assertInspectConformance({
        aep_version: "invalid"
      });
    } catch (error) {
      expect(error).toBeInstanceOf(AepConformanceError);
      expect(
        (error as AepConformanceError).issues.some((issue) => issue.path === "$.aep_version")
      ).toBe(true);
    }
  });
});

function activeEnrollment() {
  return {
    agentDid: "did:web:agent.example.com:agents:123",
    claims: {},
    createdAt: "2026-05-28T12:00:00.000Z",
    ownerActionRequired: false,
    requirementsPending: [],
    since: "2026-05-28T12:00:00.000Z",
    status: "active" as const,
    updatedAt: "2026-05-28T12:00:00.000Z"
  };
}
