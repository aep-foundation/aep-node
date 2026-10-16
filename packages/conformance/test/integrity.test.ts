import type * as FsPromises from "node:fs/promises";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

/**
 * `assertSpecArtifactIntegrity` is meant to fire when the bundled artifacts no longer match the
 * revision the manifest records. Provoking that for real would mean writing into the shipped
 * fixture tree, so the manifest read is intercepted instead and made to claim a revision the
 * artifacts cannot produce.
 */
vi.mock("node:fs/promises", async () => {
  const actual = await vi.importActual<typeof FsPromises>("node:fs/promises");

  return {
    ...actual,
    default: actual,
    readFile: async (target: Parameters<typeof actual.readFile>[0], ...rest: unknown[]) => {
      const text = await (
        actual.readFile as (
          target: Parameters<typeof actual.readFile>[0],
          ...rest: unknown[]
        ) => Promise<string>
      )(target, ...rest);

      if (typeof target === "string" && target.endsWith("manifest.json")) {
        const manifest = JSON.parse(text) as Record<string, unknown>;

        return JSON.stringify({ ...manifest, artifact_revision: "sha256:".padEnd(71, "0") });
      }

      if (
        typeof target === "string" &&
        target.endsWith(path.join("inspect", "minimal-http.json"))
      ) {
        const vector = JSON.parse(text) as Record<string, unknown>;
        return JSON.stringify({ ...vector, id: "different-identifier" });
      }

      return text;
    }
  };
});

const {
  AepConformanceError,
  assertSpecArtifactIntegrity,
  verifySpecArtifactIntegrity,
  loadTestVector
} = await import("../src/index.js");

describe("assertSpecArtifactIntegrity", () => {
  it("rejects a vector whose path does not match its metadata", async () => {
    await expect(loadTestVector("inspect/minimal-http.json")).rejects.toThrow(
      "Test vector path does not match its category and identifier."
    );
  });
  it("reports the expected and computed digests when the artifacts drift", async () => {
    const result = await verifySpecArtifactIntegrity();

    expect(result.ok).toBe(false);
    expect(result.expected).not.toBe(result.actual);
    expect(result.files).toBeGreaterThan(0);

    await expect(assertSpecArtifactIntegrity()).rejects.toBeInstanceOf(AepConformanceError);

    const error = await assertSpecArtifactIntegrity().catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(AepConformanceError);
    expect((error as InstanceType<typeof AepConformanceError>).issues).toEqual([
      {
        path: "$.artifact_revision",
        message: `Expected ${result.expected}, computed ${result.actual}.`
      }
    ]);
  });
});
