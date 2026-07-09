import { describe, expect, it } from "vitest";

import { packageName } from "../src/index.js";

describe("@aep-foundation/service-policy", () => {
  it("exports the package name", () => {
    expect(packageName).toBe("@aep-foundation/service-policy");
  });
});
