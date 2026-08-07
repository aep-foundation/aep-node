#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";

const base = process.argv[2] ?? "origin/main";
const packageManifests = git([
  "diff",
  "--name-only",
  "--diff-filter=ACDMR",
  `${base}...HEAD`,
  "--",
  "packages/**/package.json"
])
  .split("\n")
  .filter(Boolean);
const releaseRelevant = packageManifests.filter((path) => {
  const before = packageManifest(base, path);
  const after = packageManifest("HEAD", path);

  if (before === undefined || after === undefined) return true;

  delete before.devDependencies;
  delete after.devDependencies;
  return !isDeepStrictEqual(before, after);
});

if (releaseRelevant.length === 0) {
  console.log("Dependabot made no release-relevant changes to published package manifests.");
  process.exit(0);
}

console.log(
  `Dependabot changed release-relevant package manifests:\n${releaseRelevant
    .map((path) => `- ${path}`)
    .join("\n")}`
);
const result = spawnSync("pnpm", ["changeset", "status", `--since=${base}`], {
  stdio: "inherit"
});

if (result.error !== undefined) throw result.error;
process.exit(result.status ?? 1);

function git(arguments_) {
  return execFileSync("git", arguments_, { encoding: "utf8" }).trim();
}

function packageManifest(reference, path) {
  try {
    return JSON.parse(git(["show", `${reference}:${path}`]));
  } catch {
    return undefined;
  }
}
