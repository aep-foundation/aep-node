import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  AEP_CONFORMANCE_EXPECTATIONS,
  AEP_CONFORMANCE_PROFILES,
  AEP_CONFORMANCE_ROLES,
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
  assertSpecArtifactIntegrity,
  assertStatusResponseConformance,
  assertTestVector,
  exampleArtifactPath,
  loadExampleArtifact,
  loadPlatformLifecycleRequestTestVector,
  loadPlatformLifecycleResponseTestVector,
  loadPlatformProvisionResponseTestVector,
  loadPlatformSignResponseTestVector,
  loadPlatformVerificationRequestTestVector,
  loadPlatformVerificationResponseRecognizedTestVector,
  loadPlatformVerificationResponseUnrecognizedTestVector,
  loadRegistryArtifact,
  loadSchemaArtifact,
  loadSpecArtifactManifest,
  loadTestVector,
  registryArtifactPath,
  schemaArtifactPath,
  specArtifactsRoot,
  testVectorArtifactPath,
  validateBuiltInGrantResponseConformance,
  validateRevokeRequestConformance,
  validateRevokeResponseConformance,
  validateStatusResponseConformance,
  validateTestVector,
  verifySpecArtifactIntegrity
} from "../src/index.js";
import type { AepTestVector } from "../src/index.js";

function vector(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "minimal-http",
    title: "Minimal HTTP Inspect document",
    description: "A Service advertising the baseline HTTP binding.",
    drafts: ["draft-kavian-agent-enrollment-protocol-05"],
    category: "inspect",
    applicability: {
      agent: { expectation: "required", profile: "core-http" },
      platform: { expectation: "unsupported" },
      service: { expectation: "required", profile: "core-http" }
    },
    input: {},
    expected: {},
    ...overrides
  };
}

function issuePaths(result: ReturnType<typeof validateTestVector>): string[] {
  return result.ok ? [] : result.issues.map((issue) => issue.path);
}

describe("bundled artifact integrity", () => {
  it("matches the digest the manifest records", async () => {
    const result = await verifySpecArtifactIntegrity();

    expect(result.ok).toBe(true);
    expect(result.actual).toBe(result.expected);
    expect(result.files).toBeGreaterThan(100);

    await expect(assertSpecArtifactIntegrity()).resolves.toMatchObject({ ok: true });
  });

  it("covers every shipped JSON and Markdown artifact except the manifest", async () => {
    const manifest = await loadSpecArtifactManifest();
    const counted = await verifySpecArtifactIntegrity();

    const declared =
      manifest.artifacts.examples.length +
      manifest.artifacts.registry.length +
      manifest.artifacts.schemas.length +
      manifest.artifacts["test-vectors"].length;

    expect(counted.files).toBe(declared);
  });

  it("names the revision the artifacts were taken from", async () => {
    const manifest = await loadSpecArtifactManifest();

    expect(manifest.source_repository).toContain("aep-specs");
    expect(manifest.source_directory).toBe("ietf");
    expect(manifest.source_revision).toMatch(/^[0-9a-f]{40}$/);
    expect(manifest.artifact_revision).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("artifact path containment", () => {
  const escapes = [
    "../package.json",
    "../../package.json",
    "../../../../etc/passwd",
    "nested/../../manifest.json",
    "/etc/passwd"
  ];

  it("refuses a path that leaves the test vector root", () => {
    for (const relativePath of escapes) {
      expect(() => testVectorArtifactPath(relativePath), relativePath).toThrow(AepConformanceError);
    }
  });

  it("refuses a path that leaves the schema, example, or registry root", () => {
    for (const relativePath of escapes) {
      expect(() => schemaArtifactPath(relativePath)).toThrow(AepConformanceError);
      expect(() => exampleArtifactPath(relativePath)).toThrow(AepConformanceError);
      expect(() => registryArtifactPath(relativePath)).toThrow(AepConformanceError);
    }
  });

  it("refuses to read an artifact outside the bundled root", async () => {
    await expect(loadTestVector("../../../package.json")).rejects.toThrow(AepConformanceError);
    await expect(loadSchemaArtifact("../manifest.json")).rejects.toThrow(AepConformanceError);
    await expect(loadExampleArtifact("../manifest.json")).rejects.toThrow(AepConformanceError);
    await expect(loadRegistryArtifact("../manifest.json")).rejects.toThrow(AepConformanceError);
  });

  it("reports the containment failure as a conformance issue", () => {
    try {
      testVectorArtifactPath("../../../package.json");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AepConformanceError);
      expect((error as AepConformanceError).name).toBe("AepConformanceError");
      expect((error as AepConformanceError).issues).toHaveLength(1);
      expect((error as AepConformanceError).message).toContain("escapes the bundled");
    }
  });

  it("still resolves paths inside the root, including nested categories", () => {
    expect(testVectorArtifactPath("inspect/minimal-http.json")).toBe(
      path.join(specArtifactsRoot, "test-vectors", "inspect", "minimal-http.json")
    );
    expect(testVectorArtifactPath("credentials/api-key/grant-response.json")).toBe(
      path.join(specArtifactsRoot, "test-vectors", "credentials", "api-key", "grant-response.json")
    );
    expect(schemaArtifactPath("problem.schema.json")).toBe(
      path.join(specArtifactsRoot, "schemas", "problem.schema.json")
    );
  });
});

describe("package location independence", () => {
  it("resolves the bundled artifacts without consulting the working directory", async () => {
    const previous = process.cwd();

    try {
      process.chdir("/");
      const manifest = await loadSpecArtifactManifest();
      expect(manifest.source_directory).toBe("ietf");

      const loaded = await loadTestVector("inspect/minimal-http.json");
      expect(loaded.id).toBe("minimal-http");
    } finally {
      process.chdir(previous);
    }
  });
});

describe("test vector contract", () => {
  it("accepts a well-formed vector", () => {
    const result = validateTestVector(vector());

    expect(result.ok).toBe(true);
    expect(assertTestVector(vector()).id).toBe("minimal-http");
  });

  it("rejects a value that is not an object", () => {
    for (const value of [null, undefined, 7, "text", true, ["array"]]) {
      expect(issuePaths(validateTestVector(value))).toContain("$");
    }
  });

  it("requires a lowercase hyphenated identifier", () => {
    for (const id of [undefined, 7, "", "Minimal-HTTP", "minimal_http", "minimal--http", "-x"]) {
      expect(issuePaths(validateTestVector(vector({ id }))), String(id)).toContain("$.id");
    }
  });

  it("requires non-empty descriptive fields", () => {
    for (const field of ["title", "description", "category"] as const) {
      expect(issuePaths(validateTestVector(vector({ [field]: 7 })))).toContain(`$.${field}`);
      for (const value of [undefined, "", " "]) {
        expect(issuePaths(validateTestVector(vector({ [field]: value })))).toContain(`$.${field}`);
      }
    }
  });

  it("requires drafts to be a non-empty list of identifiers", () => {
    expect(issuePaths(validateTestVector(vector({ drafts: [] })))).toContain("$.drafts");
    expect(issuePaths(validateTestVector(vector({ drafts: "one" })))).toContain("$.drafts");
    expect(issuePaths(validateTestVector(vector({ drafts: [""] })))).toContain("$.drafts[0]");
    expect(issuePaths(validateTestVector(vector({ drafts: ["ok", 7] })))).toContain("$.drafts[1]");
    expect(issuePaths(validateTestVector(vector({ drafts: undefined })))).toContain("$.drafts");
  });

  it("requires input and expected to be objects", () => {
    for (const field of ["input", "expected"] as const) {
      for (const value of [undefined, "text", 7, ["array"], null]) {
        expect(issuePaths(validateTestVector(vector({ [field]: value })))).toContain(`$.${field}`);
      }
    }
  });

  it("rejects unknown categories and draft identifiers", () => {
    expect(issuePaths(validateTestVector(vector({ category: "invented" })))).toContain(
      "$.category"
    );
    expect(issuePaths(validateTestVector(vector({ drafts: ["draft-invented-00"] })))).toContain(
      "$.drafts[0]"
    );
  });
});

describe("test vector applicability", () => {
  function withApplicability(applicability: unknown): Record<string, unknown> {
    return vector({ applicability });
  }

  it("requires an applicability object", () => {
    for (const value of [undefined, "text", 7, ["array"], null]) {
      expect(issuePaths(validateTestVector(withApplicability(value)))).toContain("$.applicability");
    }
  });

  it("classifies every role exactly once", () => {
    expect(
      issuePaths(
        validateTestVector(
          withApplicability({
            agent: { expectation: "required", profile: "core-http" },
            service: { expectation: "required", profile: "core-http" }
          })
        )
      )
    ).toContain("$.applicability.platform");

    expect(
      issuePaths(
        validateTestVector(
          withApplicability({
            agent: { expectation: "required", profile: "core-http" },
            platform: { expectation: "unsupported" },
            service: { expectation: "required", profile: "core-http" },
            verifier: { expectation: "unsupported" }
          })
        )
      )
    ).toContain("$.applicability.verifier");
  });

  it("requires a classification object for each role", () => {
    expect(
      issuePaths(
        validateTestVector(
          withApplicability({
            agent: "required",
            platform: { expectation: "unsupported" },
            service: { expectation: "required", profile: "core-http" }
          })
        )
      )
    ).toContain("$.applicability.agent");
  });

  it("requires a known expectation", () => {
    expect(
      issuePaths(
        validateTestVector(
          withApplicability({
            agent: { expectation: "maybe" },
            platform: { expectation: "unsupported" },
            service: { expectation: "required", profile: "core-http" }
          })
        )
      )
    ).toContain("$.applicability.agent.expectation");
  });

  it("requires an executable classification to name a known profile", () => {
    for (const profile of [undefined, "", "future-profile", 7]) {
      expect(
        issuePaths(
          validateTestVector(
            withApplicability({
              agent: { expectation: "optional", profile },
              platform: { expectation: "unsupported" },
              service: { expectation: "required", profile: "core-http" }
            })
          )
        ),
        String(profile)
      ).toContain("$.applicability.agent.profile");
    }
  });

  it("refuses a profile on an unsupported classification", () => {
    expect(
      issuePaths(
        validateTestVector(
          withApplicability({
            agent: { expectation: "required", profile: "core-http" },
            platform: { expectation: "unsupported", profile: "platform-hosted-identity" },
            service: { expectation: "required", profile: "core-http" }
          })
        )
      )
    ).toContain("$.applicability.platform.profile");
  });

  it("accepts every published role, expectation, and profile", () => {
    expect([...AEP_CONFORMANCE_ROLES]).toEqual(["agent", "platform", "service"]);
    expect([...AEP_CONFORMANCE_EXPECTATIONS]).toEqual(["optional", "required", "unsupported"]);

    for (const profile of AEP_CONFORMANCE_PROFILES) {
      expect(
        validateTestVector(
          withApplicability({
            agent: { expectation: "optional", profile },
            platform: { expectation: "unsupported" },
            service: { expectation: "required", profile }
          })
        ).ok,
        profile
      ).toBe(true);
    }
  });

  it("throws a conformance error from the assert form", () => {
    try {
      assertTestVector(vector({ id: "Not Valid" }));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AepConformanceError);
      expect((error as AepConformanceError).issues[0]?.path).toBe("$.id");
    }
  });
});

describe("every bundled vector satisfies the contract", () => {
  it("validates all vectors named by the index", async () => {
    const index = JSON.parse(await readFile(testVectorArtifactPath("index.json"), "utf8")) as {
      vectors: string[];
    };

    expect(index.vectors.length).toBeGreaterThan(0);

    for (const relativePath of index.vectors) {
      const loaded: AepTestVector = await loadTestVector(relativePath);
      const expectedId = path.basename(relativePath, ".json");
      const expectedCategory = path.dirname(relativePath);

      expect(loaded.id, relativePath).toBe(expectedId);
      expect(loaded.category, relativePath).toBe(expectedCategory);
    }
  });

  it("indexes every vector that ships on disk", async () => {
    const index = JSON.parse(await readFile(testVectorArtifactPath("index.json"), "utf8")) as {
      vectors: string[];
    };
    const root = testVectorArtifactPath(".");
    const onDisk: string[] = [];

    const visit = async (directory: string): Promise<void> => {
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        const absolute = path.join(directory, entry.name);

        if (entry.isDirectory()) {
          await visit(absolute);
        } else if (entry.name.endsWith(".json") && entry.name !== "index.json") {
          onDisk.push(path.relative(root, absolute).split(path.sep).join("/"));
        }
      }
    };

    await visit(root);

    expect([...onDisk].sort()).toEqual([...index.vectors].sort());
  });
});

describe("malformed artifact reporting", () => {
  it("names the artifact that is not valid JSON", async () => {
    await expect(loadSchemaArtifact("README.md")).rejects.toThrow(/is not valid JSON/);

    try {
      await loadSchemaArtifact("README.md");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AepConformanceError);
      expect((error as AepConformanceError).message).toContain("README.md");
    }
  });
});

describe("conformance assertions", () => {
  it("throws for each message shape that fails validation", () => {
    const cases: Array<[string, () => unknown]> = [
      ["Inspect document", () => assertInspectConformance({})],
      ["Enroll request", () => assertEnrollRequestConformance({})],
      ["Enroll response", () => assertEnrollResponseConformance({})],
      ["Status response", () => assertStatusResponseConformance({})],
      ["Grant request", () => assertGrantRequestConformance({})],
      ["Revoke request", () => assertRevokeRequestConformance({})],
      ["Revoke response", () => assertRevokeResponseConformance({ extra: true })],
      ["Grant response", () => assertBuiltInGrantResponseConformance("oauth-bearer", {})],
      ["Claim values", () => assertClaimValuesConformance(null)],
      ["Problem Details", () => assertProblemDetailsConformance({})]
    ];

    for (const [label, run] of cases) {
      try {
        run();
        expect.unreachable();
      } catch (error) {
        expect(error, label).toBeInstanceOf(AepConformanceError);
        expect((error as AepConformanceError).issues.length, label).toBeGreaterThan(0);
      }
    }
  });

  it("returns the validated value when a message conforms", () => {
    expect(assertRevokeResponseConformance({})).toEqual({});
    expect(assertClaimValuesConformance({ "contact.email": "ops@example.com" })).toEqual({
      "contact.email": "ops@example.com"
    });
    expect(assertGrantRequestConformance({ grant_type: "oauth-bearer" })).toMatchObject({
      grant_type: "oauth-bearer"
    });
  });
});

describe("conformance validators", () => {
  it("reports issues without throwing", () => {
    expect(validateStatusResponseConformance({}).ok).toBe(false);
    expect(validateRevokeRequestConformance({}).ok).toBe(false);
    expect(validateRevokeResponseConformance({ extra: true }).ok).toBe(false);
    expect(validateBuiltInGrantResponseConformance("api-key", {}).ok).toBe(false);
  });

  it("accepts conforming messages", () => {
    expect(validateStatusResponseConformance({ status: "active" }).ok).toBe(true);
    expect(validateRevokeRequestConformance({ all_grant_types: "true" }).ok).toBe(true);
    expect(validateRevokeResponseConformance({}).ok).toBe(true);
    expect(
      validateBuiltInGrantResponseConformance("api-key", {
        api_key: "aep_live_example",
        credential_id: "key-1",
        expires_at: "2999-12-01T00:00:00Z",
        header: "x-api-key"
      }).ok
    ).toBe(true);
  });
});

describe("Platform vector loaders", () => {
  it("loads the Platform vectors that carry no typed projection", async () => {
    await expect(loadPlatformLifecycleRequestTestVector()).resolves.toMatchObject({
      id: "lifecycle-request"
    });
    await expect(loadPlatformSignResponseTestVector()).resolves.toMatchObject({
      id: "sign-response"
    });
    await expect(loadPlatformVerificationResponseRecognizedTestVector()).resolves.toMatchObject({
      id: "verification-response-recognized"
    });
    await expect(loadPlatformVerificationResponseUnrecognizedTestVector()).resolves.toMatchObject({
      id: "verification-response-unrecognized"
    });
    await expect(loadPlatformProvisionResponseTestVector()).resolves.toMatchObject({
      id: "provision-response"
    });
    await expect(loadPlatformLifecycleResponseTestVector()).resolves.toMatchObject({
      id: "lifecycle-response"
    });
    await expect(loadPlatformVerificationRequestTestVector()).resolves.toMatchObject({
      id: "verification-request"
    });
  });
});
