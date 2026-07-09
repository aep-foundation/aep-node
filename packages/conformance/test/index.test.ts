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
  loadEmptyRevokeResponseTestVector,
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
  loadSchemaArtifact,
  loadSpecArtifactManifest,
  loadTestVector,
  schemaArtifactPath,
  schemaArtifactsRoot,
  specArtifactsRoot,
  testVectorArtifactPath,
  testVectorArtifactsRoot,
  validateEnrollRequestConformance,
  validateEnrollResponseConformance,
  validateGrantRequestConformance,
  validateInspectConformance,
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

    expect(manifest.source).toBe("../aep-specs/ietf");
    expect(manifest.generated_by).toBe("scripts/sync-aep-spec-artifacts.mjs");
    expect(manifest.artifacts.schemas).toContain("inspect-document.schema.json");
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
    expect(manifest.artifacts.schemas).toContain("platform-discovery.schema.json");
    expect(manifest.artifacts.schemas).toContain("platform-provision-request.schema.json");
    expect(manifest.artifacts["test-vectors"]).toContain("platform/discovery.json");
    expect(manifest.artifacts["test-vectors"]).toContain("platform/provision-request.json");
    expect(manifest.artifacts["test-vectors"]).toContain(
      "platform/verification-response-recognized.json"
    );
  });

  it("loads schemas and test vectors by relative artifact path", async () => {
    const schema = await loadSchemaArtifact<{ title: string }>("inspect-document.schema.json");
    const vector = await loadTestVector<Record<string, never>, unknown>(
      "inspect/minimal-http.json"
    );

    expect(schema.title).toBe("AEP Inspect Document");
    expect(vector.id).toBe("minimal-http");
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
      idempotency_key: "01J0AEPPLATFORM000000000001",
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
      status: vector.expected.status
    });
  });

  it("compares @aep-foundation/service Enroll idempotency conflict output against the synced vector", async () => {
    const vector = await loadEnrollIdempotencyConflictTestVector();
    const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
    const store = createInMemoryEnrollmentStore();
    const options = {
      commandIdempotencyStore,
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
        agent_did: "did:web:agent.example.com:agents:456",
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
      owner_action_required: "false",
      requirements_pending: [],
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
  it("validates the synced minimal Inspect test vector", async () => {
    const vector = await loadMinimalInspectTestVector();

    expect(vector.id).toBe("minimal-http");
    expect(vector.expected.service.did).toBe("did:web:api.example.com");
    expect(validateInspectConformance(vector.expected).ok).toBe(true);
    expect(assertInspectConformance(vector.expected)).toEqual(vector.expected);
  });

  it("compares @aep-foundation/service Inspect output against the synced minimal vector", async () => {
    const vector = await loadMinimalInspectTestVector();
    const document = buildInspectDocument({
      serviceDid: "did:web:api.example.com",
      identityMethods: [didWebIdentityMethod()],
      grantTypes: [oauthBearerGrantType(), apiKeyGrantType(), basicGrantType()],
      claims: {
        required: ["contact.email"]
      }
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
