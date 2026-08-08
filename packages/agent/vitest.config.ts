import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    reporters: ["basic"],
    silent: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html", "lcov"]
    }
  }
});
