#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const options = parseArguments(process.argv.slice(2));
const specs = resolve(options.specsDir);
const output = resolve(options.outputDir);
const temporaryDirectory = mkdtempSync(join(tmpdir(), "aep-conformance-"));
const manifestPath = join(temporaryDirectory, "capabilities.json");
mkdirSync(output, { recursive: true });

const capabilities = JSON.parse(
  readFileSync(resolve("conformance/role-capabilities.json"), "utf8")
);
const packageMetadata = JSON.parse(
  readFileSync(resolve(`packages/${options.role}/package.json`), "utf8")
);
writeFileSync(
  manifestPath,
  JSON.stringify({
    claims: [{ profiles: capabilities[options.role], role: options.role }],
    implementation: { name: "aep-node", version: packageMetadata.version },
    manifest_version: "1"
  })
);

const result = spawnSync(
  "bundle",
  [
    "exec",
    "ruby",
    resolve(specs, "ietf/scripts/run_conformance.rb"),
    "--manifest",
    manifestPath,
    "--role",
    options.role,
    "--output",
    resolve(output, `${options.role}.json`),
    "--",
    process.execPath,
    resolve(`scripts/${options.role}-conformance-adapter.mjs`)
  ],
  { cwd: resolve(specs, "ietf"), encoding: "utf8" }
);

rmSync(temporaryDirectory, { force: true, recursive: true });
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exit(result.status ?? 1);

function parseArguments(args) {
  let outputDir = ".conformance/reports";
  let role;
  let specsDir = "../aep-specs";
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    const value = args[index + 1];
    if (argument !== "--output-dir" && argument !== "--role" && argument !== "--specs-dir") {
      throw new Error(`Unknown argument ${argument}`);
    }
    if (value === undefined) throw new Error(`${argument} requires a value`);
    if (argument === "--output-dir") outputDir = value;
    else if (argument === "--role") role = value;
    else specsDir = value;
    index += 1;
  }
  if (role !== "agent" && role !== "platform" && role !== "service") {
    throw new Error("--role requires agent, platform, or service");
  }
  return { outputDir, role, specsDir };
}
