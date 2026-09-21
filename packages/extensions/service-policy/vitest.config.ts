import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    reporters: [["default", { summary: false }]],
    silent: true,
    coverage: {
      // Report every source file, not only the ones a test happened to load. A module no test
      // imports is a coverage gap worth seeing, and a declaration-only file reports zero
      // executable lines rather than vanishing from the report entirely.
      include: ["src/**/*.ts"],
      provider: "v8",
      reporter: ["text", "json", "html", "lcov"]
    }
  }
});
