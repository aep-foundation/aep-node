#!/usr/bin/env node

import { execFileSync } from "node:child_process";

const rejectPatterns = [
  /(^|\/)\.next\//u,
  /(^|\/)\.turbo\//u,
  /(^|\/)api-docs\//u,
  /(^|\/)coverage\//u,
  /(^|\/)dist\//u,
  /(^|\/)[^/]+\.tsbuildinfo$/u
];

function stagedPaths() {
  try {
    const output = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], {
      encoding: "utf8"
    });
    return output.split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

const offenders = stagedPaths().filter((candidate) =>
  rejectPatterns.some((pattern) => pattern.test(candidate))
);

if (offenders.length > 0) {
  process.stderr.write(
    [
      "check-no-build-artifacts: refusing generated build artifacts.",
      "Remove these paths from the staged changeset:",
      ...offenders.map((offender) => `  ${offender}`),
      ""
    ].join("\n")
  );
  process.exit(1);
}
