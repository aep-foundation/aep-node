import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";

import {
  AEP_IDEMPOTENCY_KEY_HEADER,
  AEP_IDEMPOTENT_COMMANDS,
  AepAuthorizationCarrierError,
  AepIdempotencyError,
  AepServiceIdentityMismatchError,
  AepValidationError,
  assertAssertionOperationAllowed,
  assertServiceDidOriginBinding,
  createPlatformSignRequest,
  createProblemDetails,
  decodeJwtUnverified,
  didWebDocumentUrl,
  isAepAssertionOperation,
  isAssertionOperationAllowed,
  isServiceDidBoundToOrigin,
  normalizeEndpointBase,
  parseAepClaimValues,
  parseProblemDetails,
  parseProtectedResourceAuthorization,
  protectedResourceAuthorizationHeaderName,
  renderProtectedResourceAuthorization,
  resolveDidWebPublicKey,
  resolveIdempotencyKey,
  selectProtectedResourceAuthorization,
  signClientAssertionJwt,
  validateBuiltInGrantResponse,
  validateClientAssertionClaims,
  validateEnrollResponse,
  validateInspectDocument,
  validateProblemDetails,
  validateStatusResponse,
  verifyClientAssertionJwt
} from "../src/index.js";
import type { AepClientAssertionClaims, InspectDocument, ValidationResult } from "../src/index.js";

const AGENT_DID = "did:web:agent.example.com:agents:123";
const SERVICE_DID = "did:web:api.example.com";

function inspectDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    aep_version: "1.0",
    bindings: { supported: ["http"] },
    commands: { supported: ["inspect"] },
    core: { signing_algorithms: ["EdDSA", "ES256"] },
    extensions: { supported: [] },
    http: {},
    identity: { methods: ["did:web"] },
    service: { did: SERVICE_DID },
    ...overrides
  };
}

function assertionClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    aud: SERVICE_DID,
    exp: 1748428860,
    iat: 1748428800,
    iss: AGENT_DID,
    jti: "jti-1",
    op: "status",
    sub: AGENT_DID,
    ...overrides
  };
}

function paths(result: ValidationResult<unknown>): string[] {
  return result.ok ? [] : result.issues.map((issue) => issue.path);
}

describe("protected-resource credential rendering", () => {
  it("names the field for each carrier", () => {
    expect(protectedResourceAuthorizationHeaderName()).toBe("Authorization");
    expect(protectedResourceAuthorizationHeaderName("standard")).toBe("Authorization");
    expect(protectedResourceAuthorizationHeaderName("dedicated")).toBe("AEP-Authorization");
    expect(renderProtectedResourceAuthorization({ scheme: "AEP", credentials: "a.b.c" })).toEqual({
      Authorization: "AEP a.b.c"
    });
  });

  it("refuses credentials that could terminate or extend the field", () => {
    for (const credentials of [
      "",
      "token with space",
      "token\r\nX-Injected: 1",
      "tok\ten",
      "tok\u0000"
    ]) {
      expect(() => renderProtectedResourceAuthorization({ scheme: "Bearer", credentials })).toThrow(
        AepAuthorizationCarrierError
      );
    }
  });

  it("refuses a scheme that is not an AEP-recognized presentation", () => {
    expect(() =>
      renderProtectedResourceAuthorization({
        scheme: "Payment" as "Bearer",
        credentials: "token"
      })
    ).toThrow("AEP, Bearer, or Basic");
  });

  it("reports the code a Service would return for each rejection", () => {
    try {
      renderProtectedResourceAuthorization({ scheme: "Bearer", credentials: "" });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AepAuthorizationCarrierError);
      expect((error as AepAuthorizationCarrierError).code).toBe("invalid_request");
      expect((error as AepAuthorizationCarrierError).name).toBe("AepAuthorizationCarrierError");
    }

    try {
      parseProtectedResourceAuthorization("Payment secret");
      expect.unreachable();
    } catch (error) {
      expect((error as AepAuthorizationCarrierError).code).toBe("not_recognized");
    }
  });
});

describe("protected-resource credential parsing", () => {
  it("accepts the separators HTTP allows between a scheme and its credentials", () => {
    expect(parseProtectedResourceAuthorization("AEP   a.b.c")).toEqual({
      carrier: "standard",
      credentials: "a.b.c",
      scheme: "AEP"
    });
    expect(parseProtectedResourceAuthorization("bearer\ttoken")).toEqual({
      carrier: "standard",
      credentials: "token",
      scheme: "Bearer"
    });
    expect(parseProtectedResourceAuthorization("BASIC dXNlcjpwYXNz  ")).toEqual({
      carrier: "standard",
      credentials: "dXNlcjpwYXNz",
      scheme: "Basic"
    });
  });

  it("rejects presentations that are not a single recognized credential", () => {
    for (const value of ["", "AEP", "AEP ", "Payment secret", "AEP a b", "AEPa.b.c"]) {
      expect(() => parseProtectedResourceAuthorization(value)).toThrow("not recognized");
    }
  });
});

describe("protected-resource carrier selection", () => {
  it("prefers the dedicated field and never falls back past it", () => {
    expect(selectProtectedResourceAuthorization({ aepAuthorization: "AEP a.b.c" })).toEqual({
      carrier: "dedicated",
      credentials: "a.b.c",
      scheme: "AEP"
    });

    expect(
      selectProtectedResourceAuthorization({
        aepAuthorization: "Bearer dedicated-token",
        authorization: "Payment mpp-credential"
      })
    ).toEqual({ carrier: "dedicated", credentials: "dedicated-token", scheme: "Bearer" });
  });

  it("uses the standard field only when the dedicated field is absent", () => {
    expect(selectProtectedResourceAuthorization({ authorization: "Basic dXNlcg==" })).toEqual({
      carrier: "standard",
      credentials: "dXNlcg==",
      scheme: "Basic"
    });
    expect(selectProtectedResourceAuthorization({ authorization: ["AEP a.b.c"] })).toEqual({
      carrier: "standard",
      credentials: "a.b.c",
      scheme: "AEP"
    });
  });

  it("treats two AEP-recognized credentials as smuggling", () => {
    expect(() =>
      selectProtectedResourceAuthorization({
        aepAuthorization: "AEP a.b.c",
        authorization: "Bearer other"
      })
    ).toThrow("more than one AEP credential");
  });

  it("fails closed on an invalid dedicated credential rather than reading the standard field", () => {
    expect(() =>
      selectProtectedResourceAuthorization({
        aepAuthorization: "Payment nonsense",
        authorization: "Bearer valid-token"
      })
    ).toThrow("not recognized");
    expect(() =>
      selectProtectedResourceAuthorization({ aepAuthorization: "Bearer a, Basic b" })
    ).toThrow("ambiguous");
  });

  it("rejects a repeated field line in either carrier", () => {
    expect(() =>
      selectProtectedResourceAuthorization({ aepAuthorization: ["AEP a.b.c", "AEP d.e.f"] })
    ).toThrow("AEP-Authorization field must not repeat");
    expect(() =>
      selectProtectedResourceAuthorization({ authorization: ["Bearer a", "Bearer b"] })
    ).toThrow("Authorization field must not repeat");
  });

  it("reports no credential rather than a recognition failure when none is presented", () => {
    expect(selectProtectedResourceAuthorization({})).toBeUndefined();
    expect(selectProtectedResourceAuthorization({ aepAuthorization: [] })).toBeUndefined();
    expect(selectProtectedResourceAuthorization({ authorization: [] })).toBeUndefined();
    expect(
      selectProtectedResourceAuthorization({ authorization: "Payment mpp-credential" })
    ).toBeUndefined();
  });
});

describe("idempotency key resolution", () => {
  it("names the field and the commands that require it", () => {
    expect(AEP_IDEMPOTENCY_KEY_HEADER).toBe("Idempotency-Key");
    expect(AEP_IDEMPOTENT_COMMANDS).toEqual(["enroll", "grant", "revoke"]);
  });

  it("accepts a header, with or without a matching body copy", () => {
    expect(resolveIdempotencyKey({ header: "key-1" })).toBe("key-1");
    expect(resolveIdempotencyKey({ header: ["key-1"] })).toBe("key-1");
    expect(resolveIdempotencyKey({ header: "key-1", body: "key-1" })).toBe("key-1");
  });

  it("rejects a missing, empty, repeated, or contradicted key as invalid_request", () => {
    for (const input of [
      {},
      { header: "" },
      { header: [] },
      { header: ["a", "b"] },
      { header: "key-1", body: "key-2" }
    ]) {
      expect(() => resolveIdempotencyKey(input)).toThrow(AepIdempotencyError);
    }

    try {
      resolveIdempotencyKey({});
      expect.unreachable();
    } catch (error) {
      expect((error as AepIdempotencyError).code).toBe("invalid_request");
      expect((error as AepIdempotencyError).name).toBe("AepIdempotencyError");
    }
  });
});

describe("Problem Details construction", () => {
  it("derives type from code and carries the optional members", () => {
    expect(
      createProblemDetails({
        code: "verification_pending",
        title: "Verification pending",
        status: 403,
        detail: "Awaiting mailbox confirmation.",
        instance: "/aep/status",
        owner_action_required: true,
        verification_pending: ["contact.email"],
        requirements_pending: ["company.registration"]
      })
    ).toEqual({
      code: "verification_pending",
      detail: "Awaiting mailbox confirmation.",
      instance: "/aep/status",
      owner_action_required: "true",
      requirements_pending: ["company.registration"],
      status: 403,
      title: "Verification pending",
      type: "urn:aep:error:verification_pending",
      verification_pending: ["contact.email"]
    });
  });

  it("omits empty pending arrays and an unset owner action", () => {
    expect(
      createProblemDetails({
        code: "requirements_unmet",
        title: "Requirements unmet",
        status: 422,
        owner_action_required: false,
        verification_pending: [],
        requirements_pending: []
      })
    ).toEqual({
      code: "requirements_unmet",
      status: 422,
      title: "Requirements unmet",
      type: "urn:aep:error:requirements_unmet"
    });
  });

  it("never lets not_recognized disclose recognition metadata", () => {
    expect(
      createProblemDetails({
        code: "not_recognized",
        title: "Not recognized",
        status: 401,
        owner_action_required: true,
        verification_pending: ["contact.email"],
        requirements_pending: ["company.registration"]
      })
    ).toEqual({
      code: "not_recognized",
      status: 401,
      title: "Not recognized",
      type: "urn:aep:error:not_recognized"
    });
  });

  it("refuses inputs that would produce a malformed body", () => {
    expect(() => createProblemDetails({ code: "Not_Recognized", title: "t", status: 401 })).toThrow(
      "lowercase underscore-separated"
    );
    expect(() => createProblemDetails({ code: "bad code", title: "t", status: 401 })).toThrow(
      "lowercase underscore-separated"
    );
    expect(() => createProblemDetails({ code: "not_recognized", title: "", status: 401 })).toThrow(
      "non-empty title"
    );
    for (const status of [99, 600, 200.5, Number.NaN]) {
      expect(() => createProblemDetails({ code: "not_recognized", title: "t", status })).toThrow(
        "HTTP status code"
      );
    }
  });
});

describe("Problem Details validation", () => {
  it("requires a registered code shape and an HTTP status", () => {
    expect(
      paths(
        validateProblemDetails({
          type: "urn:aep:error:Not_Recognized",
          title: "Not recognized",
          status: 401,
          code: "Not_Recognized"
        })
      )
    ).toContain("$.code");

    expect(
      paths(
        validateProblemDetails({
          type: "urn:aep:error:not_recognized",
          title: "Not recognized",
          status: 42,
          code: "not_recognized"
        })
      )
    ).toContain("$.status");
  });

  it("rejects pending metadata on not_recognized", () => {
    expect(() =>
      parseProblemDetails({
        code: "not_recognized",
        status: 401,
        title: "Not recognized",
        type: "urn:aep:error:not_recognized",
        verification_pending: ["contact.email"]
      })
    ).toThrow(AepValidationError);
  });
});

describe("lifecycle pending dimensions", () => {
  it("requires pending arrays to name distinct, non-empty requirements", () => {
    expect(
      paths(
        validateEnrollResponse({
          status: "pending",
          verification_pending: ["contact.email", "contact.email"]
        })
      )
    ).toContain("$.verification_pending");

    expect(
      paths(validateStatusResponse({ status: "pending", requirements_pending: [""] }))
    ).toContain("$.requirements_pending[0]");

    expect(
      paths(validateEnrollResponse({ status: "pending", verification_pending: [] }))
    ).toContain("$.verification_pending");
  });

  it("accepts a lifecycle state reported for an existing enrollment record", () => {
    expect(validateEnrollResponse({ status: "suspended" }).ok).toBe(true);
    expect(validateStatusResponse({ status: "terminated", since: "2026-05-28T12:00:00Z" }).ok).toBe(
      true
    );
  });
});

describe("assertion operation and target binding", () => {
  it("binds each command operation to its own endpoint", () => {
    for (const command of ["enroll", "grant", "revoke", "status"] as const) {
      expect(isAssertionOperationAllowed(command, command)).toBe(true);
      expect(isAssertionOperationAllowed(command, "protected-resource")).toBe(false);
      expect(isAssertionOperationAllowed("authenticate", command)).toBe(false);
    }

    expect(isAssertionOperationAllowed("enroll", "grant")).toBe(false);
    expect(isAssertionOperationAllowed("authenticate", "protected-resource")).toBe(true);
    expect(isAssertionOperationAllowed("inspect", "protected-resource")).toBe(false);
  });

  it("throws a non-disclosing validation error on substitution", () => {
    const claims = validateClientAssertionClaims(assertionClaims({ op: "status" }));
    expect(claims.ok).toBe(true);

    if (!claims.ok) return;

    expect(() => {
      assertAssertionOperationAllowed(claims.value, "status");
    }).not.toThrow();

    try {
      assertAssertionOperationAllowed(claims.value, "enroll");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AepValidationError);
      expect((error as AepValidationError).issues).toEqual([
        { path: "$.op", message: "Expected the operation bound to this target." }
      ]);
    }
  });

  it("narrows registered assertion operations", () => {
    expect(isAepAssertionOperation("authenticate")).toBe(true);
    expect(isAepAssertionOperation("inspect")).toBe(false);
    expect(isAepAssertionOperation(7)).toBe(false);
  });
});

describe("client assertion resource binding", () => {
  it("rejects a resource that carries a fragment marker or user information", () => {
    for (const resource of [
      "https://api.example.com/v1/orders#",
      "https://api.example.com/v1/orders#section",
      "https://user:pass@api.example.com/v1/orders",
      "http://api.example.com/v1/orders",
      "not-a-uri"
    ]) {
      expect(
        paths(validateClientAssertionClaims(assertionClaims({ op: "authenticate", resource })))
      ).toContain("$.resource");
    }
  });

  it("accepts an absolute HTTPS target, and loopback only when opted in", () => {
    expect(
      validateClientAssertionClaims(
        assertionClaims({ op: "authenticate", resource: "https://api.example.com/v1/orders" })
      ).ok
    ).toBe(true);

    const loopback = assertionClaims({
      op: "authenticate",
      resource: "http://127.0.0.1:4100/v1/orders"
    });
    expect(validateClientAssertionClaims(loopback).ok).toBe(false);
    expect(validateClientAssertionClaims(loopback, { allowInsecureLoopback: true }).ok).toBe(true);
  });

  it("requires resource exactly when the operation is authenticate", () => {
    expect(paths(validateClientAssertionClaims(assertionClaims({ op: "authenticate" })))).toContain(
      "$.resource"
    );
    expect(
      paths(
        validateClientAssertionClaims(
          assertionClaims({ op: "status", resource: "https://api.example.com/v1/orders" })
        )
      )
    ).toContain("$.resource");
  });

  it("bounds the assertion lifetime to 300 seconds", () => {
    expect(validateClientAssertionClaims(assertionClaims({ iat: 0, exp: 300 })).ok).toBe(true);
    expect(paths(validateClientAssertionClaims(assertionClaims({ iat: 0, exp: 301 })))).toContain(
      "$.exp"
    );
    expect(paths(validateClientAssertionClaims(assertionClaims({ iat: 0, exp: 0 })))).toContain(
      "$.exp"
    );
  });
});

describe("Grant response expiry", () => {
  const base = { access_token: "token", credential_id: "cred-1", token_type: "Bearer" };

  it("requires an RFC 3339 date-time rather than any parseable date", () => {
    expect(
      validateBuiltInGrantResponse("oauth-bearer", {
        ...base,
        expires_at: "2026-12-01T00:00:00Z"
      }).ok
    ).toBe(true);
    expect(
      validateBuiltInGrantResponse("oauth-bearer", {
        ...base,
        expires_at: "2026-12-01T00:00:00.500+02:00"
      }).ok
    ).toBe(true);

    for (const expires_at of [
      "2026-12-01",
      "Dec 1 2026",
      "2026-02-30T00:00:00Z",
      "2026-12-01T00:00:00"
    ]) {
      expect(
        paths(validateBuiltInGrantResponse("oauth-bearer", { ...base, expires_at }))
      ).toContain("$.expires_at");
    }
  });

  it("normalizes an absent or null scope list", () => {
    const response = validateBuiltInGrantResponse("api-key", {
      api_key: "aep_live_example",
      credential_id: "key-1",
      expires_at: "2026-12-01T00:00:00Z",
      header: "x-api-key",
      scopes: null
    });

    expect(response.ok).toBe(true);
    if (response.ok) {
      expect(response.value.scopes).toEqual([]);
    }
  });
});

describe("did:web document URLs", () => {
  it("resolves root and path identifiers", () => {
    expect(String(didWebDocumentUrl("did:web:api.example.com"))).toBe(
      "https://api.example.com/.well-known/did.json"
    );
    expect(String(didWebDocumentUrl("did:web:api.example.com:agents:123"))).toBe(
      "https://api.example.com/agents/123/did.json"
    );
    expect(String(didWebDocumentUrl("did:web:%5B%3A%3A1%5D:agents:1"))).toBe(
      "https://[::1]/agents/1/did.json"
    );
  });

  it("refuses identifiers that would resolve to another origin or path", () => {
    for (const did of [
      "did:web:user%40evil.example",
      "did:web:example.com%2Fevil",
      "did:web:example.com%3Fquery",
      "did:web:example.com%23fragment",
      "did:web:example.com%5Cevil",
      "did:web:example.com:%2E%2E:etc",
      "did:web:example.com:.:etc",
      "did:web:example.com:a%2Fb"
    ]) {
      expect(() => didWebDocumentUrl(did)).toThrow(/Invalid did:web/);
    }
  });

  it("refuses a malformed identifier or an unsupported method", () => {
    expect(() => didWebDocumentUrl("did:key:z6Mk")).toThrow("Unsupported DID method");
    expect(() => didWebDocumentUrl("did:web:")).toThrow("Invalid did:web identifier");
    expect(() => didWebDocumentUrl("did:web:%E0%A4%A")).toThrow("Invalid did:web identifier");
  });

  it("downgrades to plaintext only for a syntactic loopback literal", () => {
    expect(
      String(didWebDocumentUrl("did:web:localhost%3A4100", { allowInsecureLoopback: true }))
    ).toBe("http://localhost:4100/.well-known/did.json");
    expect(
      String(didWebDocumentUrl("did:web:api.example.com", { allowInsecureLoopback: true }))
    ).toBe("https://api.example.com/.well-known/did.json");
  });
});

describe("did:web key resolution", () => {
  const publicKeyJwk = { crv: "P-256", kty: "EC", x: "example-x", y: "example-y" };

  function documentResponse(body: unknown): Promise<Response> {
    return Promise.resolve(new Response(JSON.stringify(body)));
  }

  it("selects only the verification method the kid names", async () => {
    const key = await resolveDidWebPublicKey({
      did: AGENT_DID,
      fetch: () =>
        documentResponse({
          id: AGENT_DID,
          verificationMethod: [
            { id: `${AGENT_DID}#other`, publicKeyJwk: { kty: "OKP" } },
            { id: `${AGENT_DID}#key-1`, publicKeyJwk }
          ]
        }),
      kid: `${AGENT_DID}#key-1`
    });

    expect(key).toEqual(publicKeyJwk);
  });

  it("accepts a verification method identified by a relative fragment", async () => {
    const key = await resolveDidWebPublicKey({
      did: AGENT_DID,
      fetch: () =>
        documentResponse({ id: AGENT_DID, verificationMethod: [{ id: "#key-1", publicKeyJwk }] }),
      kid: `${AGENT_DID}#key-1`
    });

    expect(key).toEqual(publicKeyJwk);
  });

  it("requires the document to identify the DID that was requested", async () => {
    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () =>
          documentResponse({
            id: "did:web:attacker.example",
            verificationMethod: [{ id: `${AGENT_DID}#key-1`, publicKeyJwk }]
          }),
        kid: `${AGENT_DID}#key-1`
      })
    ).rejects.toThrow("does not identify");

    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () => documentResponse([{ id: AGENT_DID }]),
        kid: `${AGENT_DID}#key-1`
      })
    ).rejects.toThrow("does not identify");
  });

  it("refuses to follow a redirect away from the encoded origin", async () => {
    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () =>
          Promise.resolve(
            new Response(null, { status: 302, headers: { location: "https://attacker.example/" } })
          ),
        kid: `${AGENT_DID}#key-1`
      })
    ).rejects.toThrow("Refusing to follow");
  });

  it("surfaces transport, size, and syntax failures", async () => {
    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () => Promise.resolve(new Response("", { status: 404 })),
        kid: `${AGENT_DID}#key-1`
      })
    ).rejects.toThrow("404");

    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () => Promise.resolve(new Response("x".repeat(64))),
        kid: `${AGENT_DID}#key-1`,
        maxBytes: 8
      })
    ).rejects.toThrow("exceeded 8 bytes");

    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () => Promise.resolve(new Response("{not json")),
        kid: `${AGENT_DID}#key-1`
      })
    ).rejects.toThrow("not valid JSON");
  });

  it("requires a kid that names the assertion issuer", async () => {
    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () => Promise.reject(new Error("must not fetch")),
        kid: "did:web:other.example#key-1"
      })
    ).rejects.toThrow("does not identify the assertion issuer");
  });

  it("reports a document that publishes no usable key for the kid", async () => {
    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () =>
          documentResponse({
            id: AGENT_DID,
            verificationMethod: [{ id: `${AGENT_DID}#key-1`, publicKeyMultibase: "z6Mk" }]
          }),
        kid: `${AGENT_DID}#key-1`
      })
    ).rejects.toThrow("No public JWK found");

    await expect(
      resolveDidWebPublicKey({
        did: AGENT_DID,
        fetch: () => documentResponse({ id: AGENT_DID }),
        kid: AGENT_DID
      })
    ).rejects.toThrow("No public JWK found");
  });
});

describe("Service DID origin binding", () => {
  const document = inspectDocument({
    service: { did: "did:web:api.example.com:services:primary" }
  }) as unknown as InspectDocument;

  it("binds a did:web Service DID to the origin that served Inspect", () => {
    expect(
      isServiceDidBoundToOrigin(
        "did:web:api.example.com:services:primary",
        "https://api.example.com/.well-known/aep"
      )
    ).toBe(true);
    expect(
      isServiceDidBoundToOrigin(
        "did:web:api.example.com",
        new URL("https://api.example.com/discovery/aep")
      )
    ).toBe(true);
  });

  it("rejects a mismatched origin, a port change, and an unsupported DID method", () => {
    expect(
      isServiceDidBoundToOrigin(
        "did:web:other.example.com",
        "https://api.example.com/.well-known/aep"
      )
    ).toBe(false);
    expect(
      isServiceDidBoundToOrigin(
        "did:web:api.example.com%3A8443",
        "https://api.example.com/.well-known/aep"
      )
    ).toBe(false);
    expect(
      isServiceDidBoundToOrigin("did:key:z6Mk", "https://api.example.com/.well-known/aep")
    ).toBe(false);
    expect(
      isServiceDidBoundToOrigin("did:web:user%40evil.example", "https://api.example.com/x")
    ).toBe(false);
    expect(isServiceDidBoundToOrigin("did:web:api.example.com", "not-a-url")).toBe(false);
  });

  it("throws a local service_identity_mismatch failure, not a Problem Details error", () => {
    expect(() => {
      assertServiceDidOriginBinding(document, "https://api.example.com/.well-known/aep");
    }).not.toThrow();

    try {
      assertServiceDidOriginBinding(document, "https://cdn.example.net/.well-known/aep");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AepServiceIdentityMismatchError);
      const mismatch = error as AepServiceIdentityMismatchError;
      expect(mismatch.code).toBe("service_identity_mismatch");
      expect(mismatch.name).toBe("AepServiceIdentityMismatchError");
      expect(mismatch.serviceDid).toBe("did:web:api.example.com:services:primary");
      expect(mismatch.inspectUrl).toBe("https://cdn.example.net/.well-known/aep");
    }
  });

  it("honors the loopback development option", () => {
    expect(
      isServiceDidBoundToOrigin(
        "did:web:localhost%3A4100",
        "http://localhost:4100/.well-known/aep",
        { allowInsecureLoopback: true }
      )
    ).toBe(true);
    expect(
      isServiceDidBoundToOrigin("did:web:localhost%3A4100", "http://localhost:4100/.well-known/aep")
    ).toBe(false);
  });
});

describe("OpenAPI advertisement transport", () => {
  function withOpenApi(url: string): unknown {
    return inspectDocument({
      http: { openapi: { path_matching: { trailing_slash: "strict" }, url } }
    });
  }

  it("accepts relative references and absolute HTTPS URLs", () => {
    expect(validateInspectDocument(withOpenApi("/openapi.json")).ok).toBe(true);
    expect(validateInspectDocument(withOpenApi("../openapi.json")).ok).toBe(true);
    expect(validateInspectDocument(withOpenApi("https://docs.example.net/openapi.json")).ok).toBe(
      true
    );
  });

  it("accepts plaintext only for a syntactic loopback host", () => {
    expect(validateInspectDocument(withOpenApi("http://localhost:4100/openapi.json")).ok).toBe(
      true
    );
    expect(validateInspectDocument(withOpenApi("http://127.0.0.1/openapi.json")).ok).toBe(true);
    expect(validateInspectDocument(withOpenApi("http://[::1]/openapi.json")).ok).toBe(true);
    expect(validateInspectDocument(withOpenApi("http://localtest.me/openapi.json")).ok).toBe(false);
  });

  it("rejects a downgrade or user information", () => {
    expect(
      paths(validateInspectDocument(withOpenApi("http://docs.example.net/openapi.json")))
    ).toContain("$.http.openapi.url");
    expect(
      paths(validateInspectDocument(withOpenApi("https://user:pass@docs.example.net/openapi.json")))
    ).toContain("$.http.openapi.url");
    expect(
      paths(validateInspectDocument(withOpenApi("ftp://docs.example.net/openapi.json")))
    ).toContain("$.http.openapi.url");
  });
});

describe("client assertion algorithm restriction", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const secret = new Uint8Array(32).fill(7);

  function claims(): AepClientAssertionClaims {
    const now = Math.floor(Date.now() / 1000);
    return {
      aud: SERVICE_DID,
      exp: now + 60,
      iat: now,
      iss: AGENT_DID,
      jti: "alg-test",
      op: "status",
      sub: AGENT_DID
    };
  }

  it("refuses to sign an Agent identity assertion with a symmetric or none algorithm", async () => {
    for (const alg of ["none", "HS256", "dir", "A128KW", "PBES2-HS256+A128KW"]) {
      await expect(signClientAssertionJwt(claims(), { alg, key: privateKey })).rejects.toThrow(
        "must not use the"
      );
    }
  });

  it("refuses to verify with a symmetric algorithm, however the caller asks", async () => {
    const hmac = await new SignJWT({ ...claims() })
      .setProtectedHeader({ alg: "HS256", kid: AGENT_DID, typ: "JWT" })
      .sign(secret);

    await expect(
      verifyClientAssertionJwt(hmac, { algorithms: ["HS256"], key: secret })
    ).rejects.toThrow("must not use the");

    await expect(verifyClientAssertionJwt(hmac, { key: secret })).rejects.toThrow();
  });

  it("requires at least one candidate algorithm", async () => {
    await expect(
      verifyClientAssertionJwt("a.b.c", { algorithms: [], key: secret })
    ).rejects.toThrow("at least one algorithm");
  });

  it("verifies an EdDSA assertion under the default algorithm set", async () => {
    const jwt = await signClientAssertionJwt(claims(), { alg: "EdDSA", key: privateKey });
    const verified = await verifyClientAssertionJwt(jwt, {
      audience: SERVICE_DID,
      key: publicKey
    });

    expect(verified.iss).toBe(AGENT_DID);
    expect(verified.op).toBe("status");
  });
});

describe("unverified JWT decoding", () => {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ iss: AGENT_DID })).toString("base64url");

  it("requires exactly three base64url segments", () => {
    expect(decodeJwtUnverified(`${header}.${payload}.signature`)).toEqual({
      header: { alg: "EdDSA" },
      payload: { iss: AGENT_DID }
    });

    for (const token of [
      "",
      header,
      `${header}.${payload}`,
      `${header}.${payload}.sig.extra`,
      `${header}..sig`,
      `${header}.${payload}.sig=`,
      `${header}.${payload}.sig+`
    ]) {
      expect(() => decodeJwtUnverified(token)).toThrow("Invalid JWT");
    }
  });

  it("rejects a segment that does not decode to a JSON object", () => {
    const array = Buffer.from(JSON.stringify([1, 2])).toString("base64url");

    expect(() => decodeJwtUnverified(`${header}.${array}.sig`)).toThrow("decode to an object");
  });
});

describe("Platform delegated signing requests", () => {
  it("caps the effective lifetime at the AEP maximum even when a caller asks for more", () => {
    expect(() =>
      createPlatformSignRequest({
        command: "enroll",
        jti: "jti-1",
        lifetimeSeconds: 600,
        maxLifetimeSeconds: 100000,
        serviceDid: SERVICE_DID
      })
    ).toThrow("must not exceed 300 seconds");

    expect(
      createPlatformSignRequest({
        command: "enroll",
        jti: "jti-1",
        lifetimeSeconds: 300,
        serviceDid: SERVICE_DID
      }).lifetime_seconds
    ).toBe("300");
  });

  it("still honors a shorter local maximum", () => {
    expect(() =>
      createPlatformSignRequest({
        command: "enroll",
        jti: "jti-1",
        lifetimeSeconds: 120,
        maxLifetimeSeconds: 60,
        serviceDid: SERVICE_DID
      })
    ).toThrow("must not exceed 60 seconds");
  });
});

describe("endpoint base normalization", () => {
  it("joins the command path with exactly one separator", () => {
    expect(normalizeEndpointBase()).toBe("/aep/");
    expect(normalizeEndpointBase("/aep")).toBe("/aep/");
    expect(normalizeEndpointBase("/aep/")).toBe("/aep/");
    expect(() => normalizeEndpointBase("aep")).toThrow("must start with");
  });
});

describe("claim value edge cases", () => {
  it("accepts RFC 5321 address literals in the mailbox domain", () => {
    for (const email of [
      "ops@[192.0.2.1]",
      "ops@[IPv6:2001:db8::1]",
      "ops@[IPv6:::1]",
      "ops@[IPv6:2001:db8::192.0.2.1]",
      "ops@[example-tag:literal]"
    ]) {
      expect(parseAepClaimValues({ "contact.email": email })).toEqual({ "contact.email": email });
    }
  });

  it("rejects malformed address literals", () => {
    for (const email of [
      "ops@[192.0.2.256]",
      "ops@[IPv6:2001:db8::1::2]",
      "ops@[IPv6:2001:db8:1:2:3:4:5:6:7]",
      "ops@[IPv6:zzzz::1]",
      "ops@[IPv6:2001:db8::192.0.2.999]",
      "ops@[:literal]",
      "ops@[tag:]"
    ]) {
      expect(() => parseAepClaimValues({ "contact.email": email })).toThrow(AepValidationError);
    }
  });

  it("rejects a birthdate that is not a real calendar day", () => {
    for (const birthdate of ["2025-02-30", "2025-13-01", "2025-00-10", "2100-02-29"]) {
      expect(() => parseAepClaimValues({ "person.birthdate": birthdate })).toThrow(
        AepValidationError
      );
    }
    expect(parseAepClaimValues({ "person.birthdate": "2024-02-29" })).toEqual({
      "person.birthdate": "2024-02-29"
    });
  });
});
