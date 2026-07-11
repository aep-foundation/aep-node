import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";

import {
  AEP_AUTH_SCHEME,
  AEP_BUILT_IN_GRANT_TYPES,
  AEP_GRANT_TYPE_API_KEY,
  AEP_GRANT_TYPE_BASIC,
  AEP_GRANT_TYPE_OAUTH_BEARER,
  AEP_MEDIA_TYPE,
  AEP_PROBLEM_MEDIA_TYPE,
  AEP_VERSION,
  AEP_WELL_KNOWN_PATH,
  AepValidationError,
  commandPath,
  commandPathFromInspect,
  createProblemDetails,
  decodeJwtUnverified,
  didWebDocumentUrl,
  inspectDocumentSchema,
  parseBuiltInGrantResponse,
  parseClientAssertionClaims,
  parseEnrollRequest,
  parseEnrollResponse,
  parseGrantRequest,
  parseInspectDocument,
  parseProblemDetails,
  parseRevokeRequest,
  parseRevokeResponse,
  parseStatusResponse,
  signClientAssertionJwt,
  resolveDidWebPublicKey,
  validateClientAssertionClaims,
  validateEnrollRequest,
  validateGrantRequest,
  verifyClientAssertionJwt,
  validateInspectDocument
} from "../src/index.js";
import type { AepClientAssertionClaims, InspectDocument } from "../src/index.js";

const minimalInspectDocument = {
  aep_version: "1.0",
  bindings: {
    supported: ["http"]
  },
  claims: {
    optional: [],
    preferred: [],
    required: ["contact.email"]
  },
  commands: {
    grant_types: ["oauth-bearer", "api-key", "basic"],
    supported: ["enroll", "grant", "inspect", "revoke", "status"]
  },
  core: {
    signing_algorithms: ["EdDSA", "ES256"]
  },
  extensions: {
    supported: []
  },
  http: {
    endpoint_base: "/aep/"
  },
  identity: {
    methods: ["did:web"]
  },
  service: {
    did: "did:web:api.example.com"
  }
} satisfies InspectDocument;

describe("@aep-foundation/core constants", () => {
  it("exports baseline protocol constants", () => {
    expect(AEP_VERSION).toBe("1.0");
    expect(AEP_MEDIA_TYPE).toBe("application/aep+json");
    expect(AEP_PROBLEM_MEDIA_TYPE).toBe("application/problem+json");
    expect(AEP_AUTH_SCHEME).toBe("AEP");
    expect(AEP_WELL_KNOWN_PATH).toBe("/.well-known/aep");
    expect(AEP_BUILT_IN_GRANT_TYPES).toEqual(["oauth-bearer", "api-key", "basic"]);
  });
});

describe("did:web helpers", () => {
  it("builds DID document URLs for root and path did:web identifiers", () => {
    expect(String(didWebDocumentUrl("did:web:api.example.com"))).toBe(
      "https://api.example.com/.well-known/did.json"
    );
    expect(String(didWebDocumentUrl("did:web:127.0.0.1%3A4100:agents:example-agent"))).toBe(
      "http://127.0.0.1:4100/agents/example-agent/did.json"
    );
  });

  it("resolves public keys from DID document verification methods", async () => {
    const publicKeyJwk = {
      crv: "P-256",
      kty: "EC",
      x: "example-x",
      y: "example-y"
    };
    const calls: string[] = [];
    const key = await resolveDidWebPublicKey({
      did: "did:web:agent.example.com:agents:123",
      fetch: (input) => {
        calls.push(String(input));
        return Promise.resolve(
          new Response(
            JSON.stringify({
              verificationMethod: [
                {
                  id: "did:web:agent.example.com:agents:123#key-1",
                  publicKeyJwk
                }
              ]
            })
          )
        );
      },
      kid: "did:web:agent.example.com:agents:123#key-1"
    });

    expect(calls).toEqual(["https://agent.example.com/agents/123/did.json"]);
    expect(key).toEqual(publicKeyJwk);
  });
});

describe("Inspect document validation", () => {
  it("accepts the minimal HTTP Inspect fixture shape", () => {
    const result = validateInspectDocument(minimalInspectDocument);

    expect(result.ok).toBe(true);
    expect(parseInspectDocument(minimalInspectDocument)).toEqual(minimalInspectDocument);
  });

  it("exports the Inspect JSON Schema metadata", () => {
    expect(inspectDocumentSchema.$id).toBe(
      "https://www.aep.foundation/schemas/inspect-document.schema.json"
    );
    expect(inspectDocumentSchema.required).toContain("service");
  });

  it("reports stable issue paths for invalid Inspect documents", () => {
    const result = validateInspectDocument({
      ...minimalInspectDocument,
      commands: {
        supported: ["inspect", "update"]
      },
      identity: {
        methods: []
      },
      service: {
        did: "not-a-did"
      }
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([
      { path: "$.commands.supported[1]", message: "Expected a registered AEP value." },
      { path: "$.identity.methods", message: "Expected at least 1 item(s)." },
      { path: "$.service.did", message: "Expected string to match ^did:." }
    ]);
  });

  it("throws AepValidationError from parseInspectDocument", () => {
    expect(() => parseInspectDocument(null)).toThrow(AepValidationError);
  });
});

describe("HTTP binding helpers", () => {
  it("constructs command paths with exactly one separator", () => {
    expect(commandPath("enroll", "/aep")).toBe("/aep/enroll");
    expect(commandPath("grant", "/aep/")).toBe("/aep/grant");
    expect(commandPathFromInspect(minimalInspectDocument, "status")).toBe("/aep/status");
  });

  it("rejects relative endpoint bases", () => {
    expect(() => commandPath("revoke", "aep")).toThrow(TypeError);
  });
});

describe("Problem Details helpers", () => {
  it("creates AEP Problem Details objects", () => {
    expect(
      createProblemDetails({
        code: "invalid_request",
        title: "Invalid request",
        status: 400,
        detail: "Malformed JSON."
      })
    ).toEqual({
      detail: "Malformed JSON.",
      status: 400,
      title: "Invalid request",
      type: "urn:aep:error:invalid_request",
      code: "invalid_request"
    });
  });
});

describe("Protocol message validation", () => {
  it("accepts Enroll request and response shapes", () => {
    expect(
      parseEnrollRequest({
        agent_did: "did:web:agent.example.com:agents:123",
        claims: {
          "contact.email": "ops@example.com"
        },
        idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
      })
    ).toMatchObject({
      agent_did: "did:web:agent.example.com:agents:123"
    });

    expect(
      parseEnrollResponse({
        status: "active"
      })
    ).toEqual({
      status: "active"
    });
  });

  it("reports Enroll request validation issues", () => {
    const result = validateEnrollRequest({
      agent_did: "",
      claims: [],
      idempotency_key: ""
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([
      { path: "$.agent_did", message: "Expected at least 1 character(s)." },
      { path: "$.claims", message: "Expected an object." },
      { path: "$.idempotency_key", message: "Expected at least 1 character(s)." }
    ]);
  });

  it("accepts Status response shapes", () => {
    expect(
      parseStatusResponse({
        owner_action_required: "false",
        requirements_pending: ["company.registration"],
        verification_pending: ["contact.email"],
        since: "2026-05-28T12:00:00Z",
        status: "active"
      })
    ).toEqual({
      owner_action_required: "false",
      requirements_pending: ["company.registration"],
      verification_pending: ["contact.email"],
      since: "2026-05-28T12:00:00Z",
      status: "active"
    });
  });

  it("accepts Grant and Revoke request shapes", () => {
    expect(
      parseGrantRequest({
        grant_type: "oauth-bearer",
        requested_scopes: ["read"]
      })
    ).toEqual({
      grant_type: "oauth-bearer",
      requested_scopes: ["read"]
    });

    expect(
      parseRevokeRequest({
        grant_type: "oauth-bearer"
      })
    ).toEqual({
      grant_type: "oauth-bearer"
    });

    expect(
      parseRevokeRequest({
        all_grant_types: "true"
      })
    ).toEqual({
      all_grant_types: "true"
    });

    expect(parseRevokeResponse({})).toEqual({});
  });

  it("reports Grant and Revoke validation issues", () => {
    expect(validateGrantRequest({ grant_type: "" }).issues).toEqual([
      { path: "$.grant_type", message: "Expected at least 1 character(s)." }
    ]);

    expect(() => parseRevokeRequest({})).toThrow(AepValidationError);
    expect(() =>
      parseRevokeRequest({
        all_grant_types: "true",
        grant_type: "oauth-bearer"
      })
    ).toThrow(AepValidationError);
    expect(() => parseRevokeResponse({ revoked: true })).toThrow(AepValidationError);
  });

  it("accepts baseline client assertion claim sets", () => {
    expect(
      parseClientAssertionClaims({
        aud: "did:web:api.example.com",
        exp: 1748429100,
        iat: 1748428800,
        iss: "did:web:agent.example.com:agents:123",
        jti: "01J0AEPVECTORENROLL0000000001",
        op: "enroll",
        sub: "did:web:agent.example.com:agents:123"
      })
    ).toMatchObject({
      op: "enroll"
    });

    expect(validateClientAssertionClaims({ op: "inspect" }).issues).toEqual([
      { path: "$.iss", message: "Expected a string." },
      { path: "$.sub", message: "Expected a string." },
      { path: "$.aud", message: "Expected a string." },
      { path: "$.op", message: "Expected a registered AEP value." },
      { path: "$.iat", message: "Expected an integer." },
      { path: "$.exp", message: "Expected an integer." },
      { path: "$.jti", message: "Expected a string." }
    ]);
  });

  it("accepts AEP Problem Details", () => {
    expect(
      parseProblemDetails({
        code: "not_recognized",
        status: 404,
        title: "Identity not recognized",
        type: "urn:aep:error:not_recognized"
      })
    ).toEqual({
      code: "not_recognized",
      status: 404,
      title: "Identity not recognized",
      type: "urn:aep:error:not_recognized"
    });
  });

  it("rejects pending metadata on not_recognized Problem Details", () => {
    expect(() =>
      parseProblemDetails({
        code: "not_recognized",
        status: 404,
        title: "Identity not recognized",
        type: "urn:aep:error:not_recognized",
        verification_pending: ["contact.email"]
      })
    ).toThrow(AepValidationError);
  });

  it("accepts built-in Grant response profiles", () => {
    expect(
      parseBuiltInGrantResponse(AEP_GRANT_TYPE_OAUTH_BEARER, {
        access_token: "access-token",
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        scopes: ["read"],
        token_type: "Bearer"
      })
    ).toMatchObject({
      credential_id: "cred_123",
      token_type: "Bearer"
    });

    expect(
      parseBuiltInGrantResponse(AEP_GRANT_TYPE_API_KEY, {
        api_key: "api-key",
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        header: "X-API-Key",
        scopes: []
      })
    ).toMatchObject({
      header: "X-API-Key"
    });

    expect(
      parseBuiltInGrantResponse(AEP_GRANT_TYPE_BASIC, {
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        password: "password",
        scopes: [],
        username: "username"
      })
    ).toMatchObject({
      username: "username"
    });

    expect(() => parseBuiltInGrantResponse("custom", {})).toThrow(AepValidationError);
  });
});

describe("JWT helpers", () => {
  it("decodes JWT headers and payloads without verifying trust", () => {
    const header = Buffer.from(JSON.stringify({ alg: "ES256", kid: "key-1" })).toString(
      "base64url"
    );
    const payload = Buffer.from(JSON.stringify({ iss: "did:web:agent.example.com" })).toString(
      "base64url"
    );

    expect(decodeJwtUnverified(`${header}.${payload}.signature`)).toEqual({
      header: {
        alg: "ES256",
        kid: "key-1"
      },
      payload: {
        iss: "did:web:agent.example.com"
      }
    });
  });
});

describe("Client assertion JWT helpers", () => {
  it("signs and verifies baseline client assertions with PEM keys", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: {
        format: "pem",
        type: "pkcs8"
      },
      publicKeyEncoding: {
        format: "pem",
        type: "spki"
      }
    });
    const claims = {
      aud: "did:web:api.example.com",
      exp: 1779969900,
      iat: 1779969600,
      iss: "did:web:agent.example.com:agents:123",
      jti: "jwt-helper-test",
      op: "enroll",
      sub: "did:web:agent.example.com:agents:123"
    } satisfies AepClientAssertionClaims;

    const jwt = await signClientAssertionJwt(claims, {
      alg: "ES256",
      key: {
        format: "pkcs8",
        pem: privateKey
      },
      kid: "agent-key-1"
    });

    await expect(
      verifyClientAssertionJwt(jwt, {
        algorithms: ["ES256"],
        audience: "did:web:api.example.com",
        currentDate: new Date("2026-05-28T12:00:00.000Z"),
        key: {
          format: "spki",
          pem: publicKey
        }
      })
    ).resolves.toEqual(claims);
  });
});
