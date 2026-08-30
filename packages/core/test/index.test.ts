import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { importPKCS8, SignJWT } from "jose";

import {
  AEP_AUTH_SCHEME,
  AEP_AUTHORIZATION_HEADER,
  AEP_BUILT_IN_GRANT_TYPES,
  AEP_CLAIM_NAME_CONTACT_EMAIL,
  AEP_CLAIM_NAMES,
  AEP_GRANT_TYPE_API_KEY,
  AEP_GRANT_TYPE_BASIC,
  AEP_GRANT_TYPE_OAUTH_BEARER,
  AEP_MEDIA_TYPE,
  AEP_PROBLEM_MEDIA_TYPE,
  AEP_VERSION,
  AEP_WELL_KNOWN_PATH,
  AepValidationError,
  claimValuesSchema,
  commandPath,
  commandPathFromInspect,
  createProblemDetails,
  decodeJwtUnverified,
  didWebDocumentUrl,
  evaluateAepClaimSupport,
  inspectDocumentSchema,
  isAepVersionCompatible,
  isAepClaimValues,
  missingAepRequiredClaimNames,
  parseAepClaimValues,
  parseBuiltInGrantResponse,
  parseClientAssertionClaims,
  parseEnrollRequest,
  parseEnrollResponse,
  parseGrantRequest,
  parseInspectDocument,
  parseProblemDetails,
  parseProtectedResourceAuthorization,
  parseRevokeRequest,
  parseRevokeResponse,
  parseStatusResponse,
  signClientAssertionJwt,
  renderProtectedResourceAuthorization,
  resolveDidWebPublicKey,
  validateClientAssertionClaims,
  validateAepClaimValues,
  validateEnrollRequest,
  validateGrantRequest,
  verifyClientAssertionJwt,
  validateInspectDocument
} from "../src/index.js";
import type { AepClaimValues, AepClientAssertionClaims, InspectDocument } from "../src/index.js";

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

function minimalClaims(): AepClientAssertionClaims {
  return {
    aud: "did:web:api.example.com",
    exp: 1748428860,
    iat: 1748428800,
    iss: "did:web:agent.example.com:agents:123",
    jti: "minimal-jti",
    op: "status",
    sub: "did:web:agent.example.com:agents:123"
  };

  describe("protected-resource authorization carriers", () => {
    it("parses and renders the standard and dedicated fields without changing schemes", () => {
      expect(AEP_AUTHORIZATION_HEADER).toBe("AEP-Authorization");
      expect(
        renderProtectedResourceAuthorization({
          carrier: "dedicated",
          scheme: "Bearer",
          credentials: "token"
        })
      ).toEqual({
        "AEP-Authorization": "Bearer token"
      });
      expect(parseProtectedResourceAuthorization("Basic credentials", "dedicated")).toEqual({
        carrier: "dedicated",
        credentials: "credentials",
        scheme: "Basic"
      });
    });

    it("rejects malformed and combined dedicated fields without disclosing credentials", () => {
      expect(() =>
        parseProtectedResourceAuthorization("Bearer secret, Basic other", "dedicated")
      ).toThrow("ambiguous");
      expect(() => parseProtectedResourceAuthorization("Payment secret", "dedicated")).toThrow(
        "not recognized"
      );
    });
  });
}

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

describe("AEP claim values", () => {
  const claimValues = {
    "contact.address.primary": {
      city: "San Francisco",
      country: "US",
      first_name: "Grace",
      last_name: "Hopper",
      line1: "123 Market Street",
      line3: "Attention: Receiving",
      postcode: "94105",
      region: "CA",
      future_field: "accepted"
    },
    "contact.email": "owner@example.com",
    "contact.mobile": "+14155550100",
    "person.birthdate": "1990-04-12",
    "person.first_name": "Ada",
    "person.last_name": "Lovelace",
    "person.username": "ada",
    "custom.future_claim": {
      value: "accepted"
    }
  } satisfies AepClaimValues;

  it("exports registered claim names and schema metadata", () => {
    expect(AEP_CLAIM_NAME_CONTACT_EMAIL).toBe("contact.email");
    expect(AEP_CLAIM_NAMES).toEqual([
      "contact.address.primary",
      "contact.email",
      "contact.mobile",
      "person.birthdate",
      "person.first_name",
      "person.last_name",
      "person.username"
    ]);
    expect(claimValuesSchema.$id).toBe(
      "https://www.aep.foundation/schemas/claim-values.schema.json"
    );
  });

  it("accepts known catalog values while preserving private claim names", () => {
    expect(validateAepClaimValues(claimValues).ok).toBe(true);
    expect(isAepClaimValues(claimValues)).toBe(true);
    expect(parseAepClaimValues(claimValues)).toEqual(claimValues);
  });

  it("accepts an address without a city", () => {
    expect(
      validateAepClaimValues({
        "contact.address.primary": {
          country: "US",
          first_name: "Grace",
          last_name: "Hopper",
          line1: "Rural Route 5"
        }
      }).ok
    ).toBe(true);
  });

  it("rejects the legacy postal_code address member", () => {
    const result = validateAepClaimValues({
      "contact.address.primary": {
        city: "San Francisco",
        country: "US",
        first_name: "Grace",
        last_name: "Hopper",
        line1: "123 Market Street",
        postal_code: "94105"
      }
    });

    expect(result).toEqual({
      ok: false,
      issues: [
        {
          message: "Expected the postcode member.",
          path: "$.contact.address.primary.postal_code"
        }
      ]
    });
  });

  it("accepts the minimum email shape and evaluates forward-compatible negotiation", () => {
    expect(validateAepClaimValues({ "contact.email": "a@b" }).ok).toBe(true);
    expect(
      evaluateAepClaimSupport(
        {
          required: ["contact.email", "example.future.required"],
          preferred: ["contact.mobile", "example.future.preferred"],
          optional: ["person.username", "example.future.optional"]
        },
        AEP_CLAIM_NAMES
      )
    ).toEqual({
      canSatisfyRequired: false,
      supportedOptional: ["person.username"],
      supportedPreferred: ["contact.mobile"],
      unsupportedRequired: ["example.future.required"]
    });
  });

  it("validates RFC 5321 Mailbox syntax", () => {
    for (const email of [
      "owner@example.com",
      "first.last+tag@example-domain.com",
      '"quoted local"@example.com',
      '"escaped\\"quote"@example.com',
      "owner@[192.0.2.1]",
      "owner@[IPv6:2001:db8::1]"
    ]) {
      expect(validateAepClaimValues({ "contact.email": email }).ok, email).toBe(true);
    }

    for (const email of [
      ".owner@example.com",
      "owner.@example.com",
      "owner..name@example.com",
      "owner@-example.com",
      "owner@example-.com",
      "owner@example..com",
      '"unterminated@example.com',
      "owner@[256.0.2.1]",
      "owner@[IPv6:2001:::1]",
      "ownér@example.com"
    ]) {
      expect(validateAepClaimValues({ "contact.email": email }).ok, email).toBe(false);
    }
  });

  it("finds required Claim Names that are absent from submitted values", () => {
    expect(
      missingAepRequiredClaimNames(["contact.email", "person.first_name"], {
        "contact.email": "a@b"
      })
    ).toEqual(["person.first_name"]);
  });

  it("reports stable issue paths for malformed known claims", () => {
    const result = validateAepClaimValues({
      "contact.address.primary": {
        country: "USA",
        first_name: "",
        line1: ""
      },
      "contact.email": "not-email",
      "contact.mobile": "4155550100",
      "person.birthdate": "1990-99-99",
      "person.first_name": ""
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([
      {
        path: "$.contact.address.primary.country",
        message: "Expected string to match ^[A-Z]{2}$."
      },
      {
        path: "$.contact.address.primary.first_name",
        message: "Expected at least 1 character(s)."
      },
      { path: "$.contact.address.primary.last_name", message: "Expected a string." },
      {
        path: "$.contact.address.primary.line1",
        message: "Expected at least 1 character(s)."
      },
      {
        path: "$.contact.email",
        message: "Expected an RFC 5321 Mailbox."
      },
      { path: "$.contact.mobile", message: "Expected string to match ^\\+[1-9][0-9]{1,14}$." },
      {
        path: "$.person.birthdate",
        message: "Expected an RFC 3339 full-date."
      },
      { path: "$.person.first_name", message: "Expected at least 1 character(s)." }
    ]);
  });

  it("throws AepValidationError from parseAepClaimValues", () => {
    expect(() => parseAepClaimValues(null)).toThrow(AepValidationError);
  });
});

describe("did:web helpers", () => {
  it("builds DID document URLs for root and path did:web identifiers", () => {
    expect(String(didWebDocumentUrl("did:web:api.example.com"))).toBe(
      "https://api.example.com/.well-known/did.json"
    );
    expect(String(didWebDocumentUrl("did:web:127.0.0.1%3A4100:agents:example-agent"))).toBe(
      "https://127.0.0.1:4100/agents/example-agent/did.json"
    );
    expect(
      String(
        didWebDocumentUrl("did:web:127.0.0.1%3A4100:agents:example-agent", {
          allowInsecureLoopback: true
        })
      )
    ).toBe("http://127.0.0.1:4100/agents/example-agent/did.json");
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

    await expect(
      resolveDidWebPublicKey({
        did: "did:web:agent.example.com:agents:123",
        fetch: () => Promise.reject(new Error("must not fetch")),
        kid: "did:web:different.example.com#key-1"
      })
    ).rejects.toThrow("does not identify the assertion issuer");

    await expect(
      resolveDidWebPublicKey({
        allowInsecureLoopback: true,
        did: "did:web:127.0.0.1%3A4100:agents:123",
        fetch: (input) => {
          expect(String(input)).toBe("http://127.0.0.1:4100/agents/123/did.json");
          return Promise.resolve(new Response(JSON.stringify({ verificationMethod: [] })));
        },
        kid: "did:web:127.0.0.1%3A4100:agents:123#missing"
      })
    ).rejects.toThrow("No public JWK found");
  });
});

describe("Inspect document validation", () => {
  it("accepts the minimal HTTP Inspect fixture shape", () => {
    const result = validateInspectDocument(minimalInspectDocument);

    expect(result.ok).toBe(true);
    expect(parseInspectDocument(minimalInspectDocument)).toEqual(minimalInspectDocument);
  });

  it("validates finalized OpenAPI advertisement fields", () => {
    const document = {
      ...minimalInspectDocument,
      http: {
        ...minimalInspectDocument.http,
        openapi: { path_matching: { trailing_slash: "strict" }, url: "/openapi.json" }
      }
    };
    expect(validateInspectDocument(document).ok).toBe(true);
    const invalid = validateInspectDocument({
      ...document,
      http: {
        ...document.http,
        openapi: { path_matching: { trailing_slash: "sometimes" }, url: "" }
      }
    });
    expect(invalid.ok).toBe(false);
    expect(invalid.issues).toContainEqual({
      path: "$.http.openapi.url",
      message: "Expected a non-empty string."
    });
    expect(invalid.issues).toContainEqual({
      path: "$.http.openapi.path_matching.trailing_slash",
      message: "Expected strict or equivalent."
    });
  });

  it("rejects closed Inspect objects and invalid OpenAPI references", () => {
    const result = validateInspectDocument({
      ...minimalInspectDocument,
      authentication: {
        methods: Array.from({ length: 17 }, (_, index) => `method-${index}`),
        unsupported: true
      },
      http: {
        openapi: {
          path_matching: { trailing_slash: "strict", unsupported: true },
          unsupported: true,
          url: "not a URI"
        }
      }
    });

    expect(result.issues).toContainEqual({
      path: "$.authentication.unsupported",
      message: "Expected no additional property."
    });
    expect(result.issues).toContainEqual({
      path: "$.authentication.methods",
      message: "Expected at most 16 item(s)."
    });
    expect(result.issues).toContainEqual({
      path: "$.http.openapi.unsupported",
      message: "Expected no additional property."
    });
    expect(result.issues).toContainEqual({
      path: "$.http.openapi.path_matching.unsupported",
      message: "Expected no additional property."
    });
    expect(result.issues).toContainEqual({
      path: "$.http.openapi.url",
      message: "Expected a URI reference."
    });
  });

  it("exports the Inspect JSON Schema metadata", () => {
    expect(inspectDocumentSchema.$id).toBe(
      "https://www.aep.foundation/schemas/inspect-document.schema.json"
    );
    expect(inspectDocumentSchema.required).toContain("service");
    expect("required" in inspectDocumentSchema.properties.http).toBe(false);
    expect(inspectDocumentSchema.properties.core.required).toContain("signing_algorithms");
  });

  it("accepts an Inspect-only Service without an endpoint base or identity method", () => {
    const document = {
      ...minimalInspectDocument,
      commands: { supported: ["inspect"] },
      http: {},
      identity: { methods: [] }
    } satisfies InspectDocument;

    expect(validateInspectDocument(document).ok).toBe(true);
    expect(commandPathFromInspect(document, "status")).toBe("/aep/status");
  });

  it("accepts future same-major advertisements without inferring support", () => {
    const document = {
      ...minimalInspectDocument,
      aep_version: "1.7",
      bindings: { supported: ["http", "future-binding"] },
      commands: { supported: ["inspect", "future-command"] },
      future_section: { enabled: true },
      http: {},
      identity: { methods: [] }
    } satisfies InspectDocument;

    expect(validateInspectDocument(document).ok).toBe(true);
  });

  it("enforces protocol version syntax and major-version compatibility", () => {
    expect(isAepVersionCompatible("1.0")).toBe(true);
    expect(isAepVersionCompatible("1.7")).toBe(true);
    expect(isAepVersionCompatible("1.0", "1.7")).toBe(true);
    expect(isAepVersionCompatible("2.0")).toBe(false);
    expect(isAepVersionCompatible("01.0")).toBe(false);

    expect(
      validateInspectDocument({ ...minimalInspectDocument, aep_version: "2.0" }).issues
    ).toContainEqual({
      path: "$.aep_version",
      message: "Unsupported AEP major version: 2.0."
    });
  });

  it("enforces authenticated-command and grant-type advertisements", () => {
    const missingIdentity = validateInspectDocument({
      ...minimalInspectDocument,
      identity: { methods: [] }
    });
    expect(missingIdentity.issues).toContainEqual({
      path: "$.identity.methods",
      message: "Expected at least one identity method for authenticated commands."
    });

    const missingGrantTypes = validateInspectDocument({
      ...minimalInspectDocument,
      commands: { supported: ["inspect", "grant"] }
    });
    expect(missingGrantTypes.issues).toContainEqual({
      path: "$.commands.grant_types",
      message: "Expected at least one grant type when Grant or Revoke is advertised."
    });

    const invalidConfig = validateInspectDocument({
      ...minimalInspectDocument,
      commands: {
        grant_types: ["oauth-bearer"],
        grant_types_config: {
          "api-key": { supports_per_credential_revoke: "true" },
          "oauth-bearer": { supports_per_credential_revoke: true }
        },
        supported: ["inspect", "revoke"]
      }
    });
    expect(invalidConfig.issues).toContainEqual({
      path: "$.commands.grant_types_config.api-key",
      message: "Expected configuration for an advertised grant type."
    });
    expect(invalidConfig.issues).toContainEqual({
      path: "$.commands.grant_types_config.oauth-bearer.supports_per_credential_revoke",
      message: "Expected false or true."
    });
  });

  it("enforces mandatory signing algorithms and registered-value syntax", () => {
    const result = validateInspectDocument({
      ...minimalInspectDocument,
      claims: { required: ["Contact.Email"] },
      core: { signing_algorithms: ["ES256"] },
      extensions: { supported: ["openapi-authentication"] }
    });

    expect(result.issues).toContainEqual({
      path: "$.claims.required[0]",
      message: "Expected string to match ^[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)*$."
    });
    expect(result.issues).toContainEqual({
      path: "$.core.signing_algorithms",
      message: "Expected EdDSA to be advertised."
    });
    expect(result.issues).toContainEqual({
      path: "$.extensions.supported[0]",
      message: "Expected an absolute URI."
    });
  });

  it("reports stable issue paths for invalid Inspect documents", () => {
    const result = validateInspectDocument({
      ...minimalInspectDocument,
      commands: {
        supported: ["inspect", "Invalid Command"]
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
      {
        path: "$.commands.supported[1]",
        message: "Expected string to match ^[a-z0-9]+(?:-[a-z0-9]+)*$."
      },
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

  it("accepts an Enroll request without the optional body idempotency key", () => {
    expect(
      parseEnrollRequest({
        agent_did: "did:web:agent.example.com:agents:123"
      })
    ).toEqual({
      agent_did: "did:web:agent.example.com:agents:123"
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

  it("validates known claim values in Enroll requests", () => {
    const result = validateEnrollRequest({
      agent_did: "did:web:agent.example.com:agents:123",
      claims: {
        "contact.email": "not-email"
      },
      idempotency_key: "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([
      {
        path: "$.claims.contact.email",
        message: "Expected an RFC 5321 Mailbox."
      }
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
        credential_id: "cred_123",
        grant_type: "oauth-bearer"
      })
    ).toEqual({
      credential_id: "cred_123",
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
    expect(() => parseRevokeRequest({ credential_id: "cred_123" })).toThrow(AepValidationError);
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

    expect(
      parseClientAssertionClaims({
        aud: "did:web:api.example.com",
        exp: 1748428860,
        iat: 1748428800,
        iss: "did:web:agent.example.com:agents:123",
        jti: "resource-jti",
        op: "authenticate",
        resource: "https://api.example.com/v1/orders/123",
        sub: "did:web:agent.example.com:agents:123"
      }).resource
    ).toBe("https://api.example.com/v1/orders/123");
    const loopbackClaims = {
      ...minimalClaims(),
      op: "authenticate",
      resource: "http://127.0.0.1:3000/api/resource"
    };
    expect(() => parseClientAssertionClaims(loopbackClaims)).toThrow(AepValidationError);
    expect(
      parseClientAssertionClaims(loopbackClaims, { allowInsecureLoopback: true }).resource
    ).toBe("http://127.0.0.1:3000/api/resource");
    expect(
      validateClientAssertionClaims(
        { ...loopbackClaims, resource: "http://api.example.com/resource" },
        { allowInsecureLoopback: true }
      ).ok
    ).toBe(false);
    expect(validateClientAssertionClaims({ ...minimalClaims(), op: "authenticate" }).ok).toBe(
      false
    );
    expect(
      validateClientAssertionClaims({ ...minimalClaims(), resource: "https://api.example.com" }).ok
    ).toBe(false);
    expect(
      validateClientAssertionClaims({
        ...minimalClaims(),
        sub: "did:web:different.example.com"
      }).issues
    ).toContainEqual({ path: "$.sub", message: "Expected the Agent DID from iss." });
    expect(
      validateClientAssertionClaims({ ...minimalClaims(), exp: minimalClaims().iat + 301 }).issues
    ).toContainEqual({
      path: "$.exp",
      message: "Expected a lifetime between 1 and 300 seconds."
    });
    expect(
      validateClientAssertionClaims({
        ...minimalClaims(),
        op: "authenticate",
        resource: "http://api.example.com/orders"
      }).issues
    ).toContainEqual({
      path: "$.resource",
      message: "Expected an absolute HTTPS URI without a fragment."
    });
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
        scopes: null
      })
    ).toMatchObject({
      header: "X-API-Key",
      scopes: []
    });

    expect(
      parseBuiltInGrantResponse(AEP_GRANT_TYPE_BASIC, {
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        password: "password",
        username: "username"
      })
    ).toMatchObject({
      scopes: [],
      username: "username"
    });

    expect(() =>
      parseBuiltInGrantResponse(AEP_GRANT_TYPE_API_KEY, {
        api_key: "api-key",
        credential_id: "cred_123",
        expires_at: "2026-05-28T12:00:00Z",
        header: "X-API-Key",
        scopes: [null]
      })
    ).toThrow(AepValidationError);

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
      kid: "did:web:agent.example.com:agents:123#key-1"
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

    expect(decodeJwtUnverified(jwt).header).toEqual({
      alg: "ES256",
      kid: "did:web:agent.example.com:agents:123#key-1",
      typ: "JWT"
    });

    const mismatchedKid = await new SignJWT(claims)
      .setProtectedHeader({
        alg: "ES256",
        kid: "did:web:different.example.com#key-1",
        typ: "JWT"
      })
      .sign(await importPKCS8(privateKey, "ES256"));

    await expect(
      verifyClientAssertionJwt(mismatchedKid, {
        algorithms: ["ES256"],
        audience: "did:web:api.example.com",
        currentDate: new Date("2026-05-28T12:00:00.000Z"),
        key: {
          format: "spki",
          pem: publicKey
        }
      })
    ).rejects.toThrow("kid, iss, and sub");

    const missingTyp = await new SignJWT(claims)
      .setProtectedHeader({
        alg: "ES256",
        kid: "did:web:agent.example.com:agents:123#key-1"
      })
      .sign(await importPKCS8(privateKey, "ES256"));

    await expect(
      verifyClientAssertionJwt(missingTyp, {
        algorithms: ["ES256"],
        audience: "did:web:api.example.com",
        currentDate: new Date("2026-05-28T12:00:00.000Z"),
        key: {
          format: "spki",
          pem: publicKey
        }
      })
    ).rejects.toThrow("JOSE header");
  });
});
