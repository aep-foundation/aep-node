import { describe, expect, it, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { exportPKCS8, exportSPKI, SignJWT } from "jose";

import {
  didWebDocumentUrl,
  evaluateAepClaimSupport,
  importJoseKey,
  importJwkJoseKey,
  isAepClaimValues,
  isInspectDocument,
  missingAepRequiredClaimNames,
  parseAepClaimValues,
  resolveDidWebPublicKey,
  signClientAssertionJwt,
  validateAepClaimValues,
  validateApiKeyGrantResponse,
  validateBasicGrantResponse,
  validateBuiltInGrantResponse,
  validateClientAssertionClaims,
  validateEnrollRequest,
  validateEnrollResponse,
  validateGrantRequest,
  validateInspectDocument,
  validateOAuthBearerGrantResponse,
  validateProblemDetails,
  validateRevokeRequest,
  validateRevokeResponse,
  validateStatusResponse,
  verifyClientAssertionJwt
} from "../src/index.js";
import type { AepClaimValues, ValidationResult } from "../src/index.js";

const AGENT_DID = "did:web:agent.example.com:agents:123";
const SERVICE_DID = "did:web:api.example.com";

function paths(result: ValidationResult<unknown>): string[] {
  return result.ok ? [] : result.issues.map((issue) => issue.path);
}

function inspectDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    aep_version: "1.0",
    bindings: { supported: ["http"] },
    commands: { supported: ["inspect"] },
    core: { signing_algorithms: ["EdDSA", "ES256"] },
    http: {},
    identity: { methods: ["did:web"] },
    service: { did: SERVICE_DID },
    ...overrides
  };
}

describe("validator root guards", () => {
  const validators = {
    validateEnrollRequest,
    validateEnrollResponse,
    validateStatusResponse,
    validateGrantRequest,
    validateRevokeRequest,
    validateRevokeResponse,
    validateClientAssertionClaims,
    validateProblemDetails,
    validateOAuthBearerGrantResponse,
    validateApiKeyGrantResponse,
    validateBasicGrantResponse,
    validateAepClaimValues,
    validateInspectDocument
  };

  it("reports a non-object payload as a root issue rather than throwing", () => {
    for (const [name, validate] of Object.entries(validators)) {
      for (const value of [null, undefined, 7, "text", true, ["array"]]) {
        const result = validate(value);
        expect(result.ok, `${name} accepted ${String(value)}`).toBe(false);
        expect(paths(result)).toContain("$");
      }
    }
  });

  it("exposes the boolean narrowing helpers", () => {
    expect(isInspectDocument(inspectDocument())).toBe(true);
    expect(isInspectDocument({})).toBe(false);
    expect(isAepClaimValues({ "contact.email": "ops@example.com" })).toBe(true);
    expect(isAepClaimValues({ "contact.email": 7 })).toBe(false);
  });

  it("reports an unregistered grant type rather than guessing a profile", () => {
    expect(paths(validateBuiltInGrantResponse("future-credential", {}))).toEqual(["$.grant_type"]);
  });
});

describe("Inspect document structure", () => {
  it("requires every mandatory section to be an object", () => {
    for (const section of ["bindings", "commands", "core", "http", "identity", "service"]) {
      expect(paths(validateInspectDocument(inspectDocument({ [section]: "text" })))).toContain(
        `$.${section}`
      );
      expect(paths(validateInspectDocument(inspectDocument({ [section]: undefined })))).toContain(
        `$.${section}`
      );
    }

    for (const section of ["authentication", "claims", "extensions"]) {
      expect(paths(validateInspectDocument(inspectDocument({ [section]: "text" })))).toContain(
        `$.${section}`
      );
    }
  });

  it("checks the protocol version syntax and compatibility family", () => {
    expect(paths(validateInspectDocument(inspectDocument({ aep_version: 1 })))).toContain(
      "$.aep_version"
    );
    for (const aep_version of ["1", "01.0", "1.0.0", "1.-1"]) {
      expect(paths(validateInspectDocument(inspectDocument({ aep_version })))).toContain(
        "$.aep_version"
      );
    }
    expect(paths(validateInspectDocument(inspectDocument({ aep_version: "2.0" })))).toContain(
      "$.aep_version"
    );
    expect(validateInspectDocument(inspectDocument({ aep_version: "1.7" })).ok).toBe(true);
  });

  it("requires the advertised binding and command baselines", () => {
    expect(
      paths(validateInspectDocument(inspectDocument({ bindings: { supported: ["future"] } })))
    ).toContain("$.bindings.supported");
    expect(
      paths(validateInspectDocument(inspectDocument({ bindings: { supported: "http" } })))
    ).toContain("$.bindings.supported");
    expect(
      paths(validateInspectDocument(inspectDocument({ bindings: { supported: [] } })))
    ).toContain("$.bindings.supported");
    expect(
      paths(validateInspectDocument(inspectDocument({ commands: { supported: ["enroll"] } })))
    ).toContain("$.commands.supported");
    expect(
      paths(validateInspectDocument(inspectDocument({ bindings: { supported: ["http", 7] } })))
    ).toContain("$.bindings.supported[1]");
    expect(
      paths(
        validateInspectDocument(inspectDocument({ bindings: { supported: ["http", "Not-Lower"] } }))
      )
    ).toContain("$.bindings.supported[1]");
  });

  it("requires both baseline signing algorithms", () => {
    expect(
      paths(validateInspectDocument(inspectDocument({ core: { signing_algorithms: ["ES256"] } })))
    ).toContain("$.core.signing_algorithms");
    expect(
      paths(validateInspectDocument(inspectDocument({ core: { signing_algorithms: [] } })))
    ).toContain("$.core.signing_algorithms");
    expect(
      paths(validateInspectDocument(inspectDocument({ core: { signing_algorithms: "EdDSA" } })))
    ).toContain("$.core.signing_algorithms");
    expect(
      validateInspectDocument(
        inspectDocument({ core: { signing_algorithms: ["EdDSA", "ES256", "ES384"] } })
      ).ok
    ).toBe(true);
  });

  it("ties grant type configuration to the advertised grant types", () => {
    const withCommands = (commands: unknown): unknown => inspectDocument({ commands });

    expect(
      paths(
        validateInspectDocument(
          withCommands({ supported: ["inspect"], grant_types_config: "text" })
        )
      )
    ).toContain("$.commands.grant_types_config");

    expect(
      paths(
        validateInspectDocument(
          withCommands({
            supported: ["inspect"],
            grant_types: ["oauth-bearer"],
            grant_types_config: { "Not-Lower": {} }
          })
        )
      )
    ).toContain("$.commands.grant_types_config.Not-Lower");

    expect(
      paths(
        validateInspectDocument(
          withCommands({
            supported: ["inspect"],
            grant_types: ["oauth-bearer"],
            grant_types_config: { "api-key": {} }
          })
        )
      )
    ).toContain("$.commands.grant_types_config.api-key");

    expect(
      paths(
        validateInspectDocument(
          withCommands({
            supported: ["inspect"],
            grant_types: ["oauth-bearer"],
            grant_types_config: { "oauth-bearer": "text" }
          })
        )
      )
    ).toContain("$.commands.grant_types_config.oauth-bearer");

    expect(
      paths(
        validateInspectDocument(
          withCommands({
            supported: ["inspect"],
            grant_types: ["oauth-bearer"],
            grant_types_config: { "oauth-bearer": { supports_per_credential_revoke: true } }
          })
        )
      )
    ).toContain("$.commands.grant_types_config.oauth-bearer.supports_per_credential_revoke");

    expect(
      validateInspectDocument(
        withCommands({
          supported: ["inspect", "grant", "revoke"],
          grant_types: ["oauth-bearer"],
          grant_types_config: { "oauth-bearer": { supports_per_credential_revoke: "true" } }
        })
      ).ok
    ).toBe(true);
  });

  it("requires an identity method for authenticated commands", () => {
    expect(
      paths(
        validateInspectDocument(
          inspectDocument({
            commands: { supported: ["inspect", "status"] },
            identity: { methods: [] }
          })
        )
      )
    ).toContain("$.identity.methods");
    expect(
      paths(validateInspectDocument(inspectDocument({ identity: { methods: "did:web" } })))
    ).toContain("$.identity.methods");
    expect(
      paths(validateInspectDocument(inspectDocument({ identity: { methods: ["DID:WEB"] } })))
    ).toContain("$.identity.methods[0]");
    expect(
      validateInspectDocument(
        inspectDocument({ commands: { supported: ["inspect"] }, identity: { methods: [] } })
      ).ok
    ).toBe(true);
  });

  it("requires extension identifiers to be absolute URIs", () => {
    expect(
      paths(
        validateInspectDocument(
          inspectDocument({ extensions: { supported: ["openapi-authentication"] } })
        )
      )
    ).toContain("$.extensions.supported[0]");
    expect(
      validateInspectDocument(
        inspectDocument({ extensions: { supported: ["urn:aep:ext:example:demo#v=1"] } })
      ).ok
    ).toBe(true);
    expect(validateInspectDocument(inspectDocument({ extensions: {} })).ok).toBe(true);
  });

  it("validates the OpenAPI advertisement shape", () => {
    const withHttp = (http: unknown): unknown => inspectDocument({ http });

    expect(paths(validateInspectDocument(withHttp({ endpoint_base: "aep" })))).toContain(
      "$.http.endpoint_base"
    );
    expect(paths(validateInspectDocument(withHttp({ openapi: "text" })))).toContain(
      "$.http.openapi"
    );
    expect(
      paths(
        validateInspectDocument(
          withHttp({ openapi: { url: "/openapi.json", path_matching: "text" } })
        )
      )
    ).toContain("$.http.openapi.path_matching");
    expect(
      paths(
        validateInspectDocument(
          withHttp({
            openapi: { url: "/openapi.json", path_matching: { trailing_slash: "loose" } }
          })
        )
      )
    ).toContain("$.http.openapi.path_matching.trailing_slash");
    expect(
      paths(
        validateInspectDocument(
          withHttp({
            openapi: {
              url: "/openapi.json",
              path_matching: { trailing_slash: "strict" },
              extra: true
            }
          })
        )
      )
    ).toContain("$.http.openapi.extra");
    expect(
      paths(
        validateInspectDocument(
          withHttp({ openapi: { url: "", path_matching: { trailing_slash: "strict" } } })
        )
      )
    ).toContain("$.http.openapi.url");
    expect(
      paths(
        validateInspectDocument(
          withHttp({ openapi: { url: "not a URI", path_matching: { trailing_slash: "strict" } } })
        )
      )
    ).toContain("$.http.openapi.url");
    expect(
      paths(
        validateInspectDocument(
          withHttp({ openapi: { url: 7, path_matching: { trailing_slash: "strict" } } })
        )
      )
    ).toContain("$.http.openapi.url");
  });

  it("rejects unknown members where the schema closes the object", () => {
    expect(
      paths(
        validateInspectDocument(
          inspectDocument({ authentication: { methods: ["aep-jwt"], extra: true } })
        )
      )
    ).toContain("$.authentication.extra");
    expect(
      paths(
        validateInspectDocument(
          inspectDocument({ authentication: { methods: ["aep-jwt", "aep-jwt"] } })
        )
      )
    ).toContain("$.authentication.methods");
    expect(
      paths(validateInspectDocument(inspectDocument({ authentication: { methods: [] } })))
    ).toContain("$.authentication.methods");
  });

  it("requires a DID for the Service identity", () => {
    expect(
      paths(validateInspectDocument(inspectDocument({ service: { did: "api.example.com" } })))
    ).toContain("$.service.did");
    expect(paths(validateInspectDocument(inspectDocument({ service: {} })))).toContain(
      "$.service.did"
    );
  });

  it("checks claim name syntax in every advertisement list", () => {
    for (const list of ["required", "preferred", "optional"]) {
      expect(
        paths(validateInspectDocument(inspectDocument({ claims: { [list]: ["Contact.Email"] } })))
      ).toContain(`$.claims.${list}[0]`);
      expect(
        paths(validateInspectDocument(inspectDocument({ claims: { [list]: "contact.email" } })))
      ).toContain(`$.claims.${list}`);
    }
    expect(validateInspectDocument(inspectDocument({ claims: {} })).ok).toBe(true);
  });
});

describe("Revoke request targeting", () => {
  it("accepts exactly one target shape", () => {
    expect(validateRevokeRequest({ grant_type: "oauth-bearer" }).ok).toBe(true);
    expect(validateRevokeRequest({ grant_type: "oauth-bearer", credential_id: "c1" }).ok).toBe(
      true
    );
    expect(validateRevokeRequest({ all_grant_types: "true" }).ok).toBe(true);
  });

  it("rejects an absent, conflicting, or partial target", () => {
    expect(paths(validateRevokeRequest({}))).toContain("$");
    expect(paths(validateRevokeRequest({ credential_id: "c1" }))).toContain("$");
    expect(
      paths(validateRevokeRequest({ all_grant_types: "true", grant_type: "oauth-bearer" }))
    ).toContain("$");
    expect(
      paths(validateRevokeRequest({ all_grant_types: "true", credential_id: "c1" }))
    ).toContain("$");
    expect(paths(validateRevokeRequest({ all_grant_types: "false" }))).toContain(
      "$.all_grant_types"
    );
    expect(paths(validateRevokeRequest({ grant_type: "" }))).toContain("$.grant_type");
  });

  it("requires the Revoke response to be strictly empty", () => {
    expect(validateRevokeResponse({}).ok).toBe(true);
    expect(paths(validateRevokeResponse({ revoked: 1 }))).toContain("$");
  });
});

describe("request and response field types", () => {
  it("reports Enroll and Grant field type issues", () => {
    expect(paths(validateEnrollRequest({}))).toContain("$.agent_did");
    expect(paths(validateEnrollRequest({ agent_did: "" }))).toContain("$.agent_did");
    expect(paths(validateEnrollRequest({ agent_did: AGENT_DID, idempotency_key: "" }))).toContain(
      "$.idempotency_key"
    );
    expect(
      paths(validateEnrollRequest({ agent_did: AGENT_DID, claims: { "contact.email": 7 } }))
    ).toContain("$.claims.contact.email");
    expect(paths(validateEnrollRequest({ agent_did: AGENT_DID, claims: "text" }))).toContain(
      "$.claims"
    );
    expect(
      paths(validateGrantRequest({ grant_type: "oauth-bearer", requested_scopes: "read" }))
    ).toContain("$.requested_scopes");
    expect(
      paths(validateGrantRequest({ grant_type: "oauth-bearer", requested_scopes: ["read", 7] }))
    ).toContain("$.requested_scopes[1]");
  });

  it("reports lifecycle field type issues", () => {
    expect(paths(validateEnrollResponse({ status: "unknown" }))).toContain("$.status");
    expect(
      paths(validateStatusResponse({ status: "active", owner_action_required: "yes" }))
    ).toContain("$.owner_action_required");
    expect(paths(validateStatusResponse({ status: "active", since: 7 }))).toContain("$.since");
    expect(
      paths(validateEnrollResponse({ status: "pending", verification_pending: "contact.email" }))
    ).toContain("$.verification_pending");
    expect(
      paths(validateEnrollResponse({ status: "pending", verification_pending: [7] }))
    ).toContain("$.verification_pending[0]");
  });

  it("reports credential profile field issues", () => {
    expect(
      paths(validateOAuthBearerGrantResponse({ access_token: "t", credential_id: "c" }))
    ).toContain("$.expires_at");
    expect(
      paths(
        validateOAuthBearerGrantResponse({
          access_token: "t",
          credential_id: "c",
          expires_at: "2026-12-01T00:00:00Z",
          token_type: "Mac"
        })
      )
    ).toContain("$.token_type");
    expect(
      paths(
        validateApiKeyGrantResponse({
          api_key: "k",
          credential_id: "c",
          expires_at: "2026-12-01T00:00:00Z"
        })
      )
    ).toContain("$.header");
    expect(
      paths(
        validateBasicGrantResponse({
          credential_id: "c",
          expires_at: "2026-12-01T00:00:00Z",
          password: "p",
          realm: "",
          username: "u"
        })
      )
    ).toContain("$.realm");
    expect(
      paths(
        validateBasicGrantResponse({
          credential_id: "c",
          expires_at: "2026-12-01T00:00:00Z",
          password: "p",
          scopes: "read",
          username: "u"
        })
      )
    ).toContain("$.scopes");
    expect(
      validateBasicGrantResponse({
        credential_id: "c",
        expires_at: "2026-12-01T00:00:00Z",
        password: "p",
        realm: "api.example.com",
        username: "u"
      }).ok
    ).toBe(true);
  });

  it("reports client assertion field issues", () => {
    expect(paths(validateClientAssertionClaims({}))).toEqual(
      expect.arrayContaining(["$.iss", "$.sub", "$.aud", "$.op", "$.iat", "$.exp", "$.jti"])
    );
    expect(
      paths(
        validateClientAssertionClaims({
          aud: SERVICE_DID,
          exp: 1748428860,
          iat: 1748428800,
          iss: AGENT_DID,
          jti: "j",
          op: "inspect",
          sub: AGENT_DID
        })
      )
    ).toContain("$.op");
    expect(
      paths(
        validateClientAssertionClaims({
          aud: SERVICE_DID,
          exp: 1748428860,
          iat: 1748428800,
          iss: AGENT_DID,
          jti: "j",
          op: "status",
          sub: "did:web:other.example"
        })
      )
    ).toContain("$.sub");
    expect(
      paths(
        validateClientAssertionClaims({
          aud: SERVICE_DID,
          exp: "later",
          iat: 1748428800,
          iss: AGENT_DID,
          jti: "j",
          op: "status",
          sub: AGENT_DID
        })
      )
    ).toContain("$.exp");
  });
});

describe("claim value shapes", () => {
  it("validates the primary address object", () => {
    expect(paths(validateAepClaimValues({ "contact.address.primary": "text" }))).toContain(
      "$.contact.address.primary"
    );
    expect(
      paths(
        validateAepClaimValues({
          "contact.address.primary": {
            country: "US",
            first_name: "Grace",
            last_name: "Hopper",
            line1: "123 Market Street",
            postal_code: "94105"
          }
        })
      )
    ).toContain("$.contact.address.primary.postal_code");
    expect(
      paths(
        validateAepClaimValues({
          "contact.address.primary": {
            city: "",
            country: "us",
            first_name: "Grace",
            last_name: "Hopper",
            line1: "123 Market Street"
          }
        })
      )
    ).toEqual(
      expect.arrayContaining([
        "$.contact.address.primary.city",
        "$.contact.address.primary.country"
      ])
    );
    expect(
      validateAepClaimValues({
        "contact.address.primary": {
          city: "San Francisco",
          country: "US",
          first_name: "Grace",
          last_name: "Hopper",
          line1: "123 Market Street",
          line2: "Floor 4",
          line3: "Attention: Receiving",
          postcode: "94105",
          region: "CA"
        }
      }).ok
    ).toBe(true);
  });

  it("validates quoted mailbox local parts", () => {
    for (const email of ['"quoted local"@example.com', '"escaped\\"quote"@example.com']) {
      expect(parseAepClaimValues({ "contact.email": email })).toEqual({ "contact.email": email });
    }

    for (const email of [
      '"unterminated@example.com',
      '"badchar"@example.com',
      '"trailing\\"@example.com',
      '"quoted"x@example.com',
      '"@example.com'
    ]) {
      expect(isAepClaimValues({ "contact.email": email })).toBe(false);
    }
  });

  it("rejects a mailbox with more than one separator or an unbalanced literal", () => {
    for (const email of ["a@b@c", "ops@[192.0.2.1", "ops@192.0.2.1]", "@example.com", "ops@"]) {
      expect(isAepClaimValues({ "contact.email": email })).toBe(false);
    }
  });

  it("bounds the mobile and name shapes", () => {
    for (const mobile of ["+0123456789", "+1", "14155550100", "+1415555010012345678"]) {
      expect(paths(validateAepClaimValues({ "contact.mobile": mobile }))).toContain(
        "$.contact.mobile"
      );
    }
    expect(paths(validateAepClaimValues({ "person.first_name": "" }))).toContain(
      "$.person.first_name"
    );
    expect(paths(validateAepClaimValues({ "person.last_name": 7 }))).toContain(
      "$.person.last_name"
    );
    expect(paths(validateAepClaimValues({ "person.username": "" }))).toContain("$.person.username");
    expect(paths(validateAepClaimValues({ "person.birthdate": "20250101" }))).toContain(
      "$.person.birthdate"
    );
  });
});

describe("claim negotiation", () => {
  it("separates satisfiable requirements from unsupported ones", () => {
    expect(
      evaluateAepClaimSupport(
        {
          required: ["contact.email", "example.future.required"],
          preferred: ["contact.mobile", "example.future.preferred"],
          optional: ["person.username", "example.future.optional"]
        },
        ["contact.email", "contact.mobile", "person.username"]
      )
    ).toEqual({
      canSatisfyRequired: false,
      supportedOptional: ["person.username"],
      supportedPreferred: ["contact.mobile"],
      unsupportedRequired: ["example.future.required"]
    });
  });

  it("treats an absent advertisement as nothing requested", () => {
    expect(evaluateAepClaimSupport(undefined, ["contact.email"])).toEqual({
      canSatisfyRequired: true,
      supportedOptional: [],
      supportedPreferred: [],
      unsupportedRequired: []
    });
    expect(evaluateAepClaimSupport({}, [])).toEqual({
      canSatisfyRequired: true,
      supportedOptional: [],
      supportedPreferred: [],
      unsupportedRequired: []
    });
  });

  it("reports required claim names with no submitted value", () => {
    expect(missingAepRequiredClaimNames(["contact.email"], undefined)).toEqual(["contact.email"]);
    expect(missingAepRequiredClaimNames(["contact.email"], {})).toEqual(["contact.email"]);
    const explicitlyUndefined = { "contact.email": undefined } as unknown as AepClaimValues;
    expect(missingAepRequiredClaimNames(["contact.email"], explicitlyUndefined)).toEqual([
      "contact.email"
    ]);
    expect(
      missingAepRequiredClaimNames(["contact.email"], { "contact.email": "ops@example.com" })
    ).toEqual([]);
  });
});

describe("JOSE key import", () => {
  const ed25519 = generateKeyPairSync("ed25519");
  const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" });

  it("passes through keys that need no import", async () => {
    await expect(importJoseKey(ed25519.privateKey)).resolves.toBe(ed25519.privateKey);
  });

  it("imports PEM keys in each supported format", async () => {
    const pkcs8 = await exportPKCS8(p256.privateKey);
    const spki = await exportSPKI(p256.publicKey);

    await expect(importJoseKey({ format: "pkcs8", pem: pkcs8 }, "ES256")).resolves.toBeDefined();
    await expect(importJoseKey({ format: "spki", pem: spki }, "ES256")).resolves.toBeDefined();
  });

  it("requires an algorithm for a PEM import", async () => {
    const pkcs8 = await exportPKCS8(p256.privateKey);

    await expect(importJoseKey({ format: "pkcs8", pem: pkcs8 })).rejects.toThrow(
      "requires an algorithm"
    );
  });

  it("imports a JWK", async () => {
    await expect(
      importJwkJoseKey(
        { crv: "Ed25519", kty: "OKP", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
        "EdDSA"
      )
    ).resolves.toBeDefined();
  });
});

describe("client assertion verification options", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");

  function claims(): Record<string, unknown> {
    const now = Math.floor(Date.now() / 1000);
    return {
      aud: SERVICE_DID,
      exp: now + 60,
      iat: now,
      iss: AGENT_DID,
      jti: "verify-options",
      op: "status",
      sub: AGENT_DID
    };
  }

  it("passes issuer, subject, and clock tolerance through to verification", async () => {
    const jwt = await signClientAssertionJwt(claims() as never, { alg: "EdDSA", key: privateKey });

    const verified = await verifyClientAssertionJwt(jwt, {
      audience: SERVICE_DID,
      clockTolerance: 30,
      currentDate: new Date(),
      issuer: AGENT_DID,
      key: publicKey,
      subject: AGENT_DID
    });

    expect(verified.jti).toBe("verify-options");

    await expect(
      verifyClientAssertionJwt(jwt, { issuer: "did:web:other.example", key: publicKey })
    ).rejects.toThrow();
  });

  it("resolves the key from the protected header when given a resolver", async () => {
    const jwt = await signClientAssertionJwt(claims() as never, {
      alg: "EdDSA",
      key: privateKey,
      kid: `${AGENT_DID}#key-1`
    });
    const seen: string[] = [];

    const verified = await verifyClientAssertionJwt(jwt, {
      key: (header) => {
        seen.push(String(header.kid));
        return publicKey;
      }
    });

    expect(seen).toEqual([`${AGENT_DID}#key-1`]);
    expect(verified.sub).toBe(AGENT_DID);
  });

  it("rejects a header whose kid does not identify the issuer", async () => {
    const mismatched = await new SignJWT(claims())
      .setProtectedHeader({ alg: "EdDSA", kid: "did:web:other.example", typ: "JWT" })
      .sign(privateKey);

    await expect(verifyClientAssertionJwt(mismatched, { key: publicKey })).rejects.toThrow(
      "must identify the same Agent DID"
    );
  });

  it("rejects a signing request whose kid does not identify the issuer", async () => {
    await expect(
      signClientAssertionJwt(claims() as never, {
        alg: "EdDSA",
        key: privateKey,
        kid: "did:web:other.example"
      })
    ).rejects.toThrow("must identify the same Agent DID");
  });
});

describe("did:web resolution environment", () => {
  it("requires a fetch implementation when the runtime has none", async () => {
    vi.stubGlobal("fetch", undefined);

    try {
      await expect(
        resolveDidWebPublicKey({ did: AGENT_DID, kid: `${AGENT_DID}#key-1` })
      ).rejects.toThrow("requires a fetch implementation");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects a host whose port cannot be parsed", () => {
    expect(() => didWebDocumentUrl("did:web:example.com%3A99999")).toThrow("Invalid did:web host");
  });

  it("keeps the port of a bracketed IPv6 host", () => {
    expect(String(didWebDocumentUrl("did:web:%5B%3A%3A1%5D%3A4100:agents:1"))).toBe(
      "https://[::1]:4100/agents/1/did.json"
    );
  });
});

describe("remaining validation branches", () => {
  it("rejects an OpenAPI reference the URL parser cannot resolve", () => {
    const document = {
      aep_version: "1.0",
      bindings: { supported: ["http"] },
      commands: { supported: ["inspect"] },
      core: { signing_algorithms: ["EdDSA", "ES256"] },
      http: { openapi: { url: "http://[", path_matching: { trailing_slash: "strict" } } },
      identity: { methods: ["did:web"] },
      service: { did: SERVICE_DID }
    };

    expect(paths(validateInspectDocument(document))).toContain("$.http.openapi.url");
  });

  it("rejects an expiry whose month or day is out of range", () => {
    const base = { access_token: "t", credential_id: "c", token_type: "Bearer" };

    for (const expires_at of ["2026-13-01T00:00:00Z", "2026-12-00T00:00:00Z"]) {
      expect(paths(validateOAuthBearerGrantResponse({ ...base, expires_at }))).toContain(
        "$.expires_at"
      );
    }
  });

  it("imports an X.509 PEM through the certificate path", async () => {
    await expect(
      importJoseKey(
        { format: "x509", pem: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----" },
        "ES256"
      )
    ).rejects.toThrow();
  });
});
