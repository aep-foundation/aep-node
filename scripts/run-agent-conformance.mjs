#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

const options = parseArguments(process.argv.slice(2));
const specs = resolve(options.specsDir);
const output = resolve(options.outputDir);
mkdirSync(output, { recursive: true });

const result = spawnSync(
  "bundle",
  [
    "exec",
    "ruby",
    resolve(specs, "ietf/scripts/run_conformance.rb"),
    "--manifest",
    resolve("conformance/agent-capabilities.json"),
    "--role",
    "agent",
    "--output",
    resolve(output, "agent.json"),
    "--",
    process.execPath,
    resolve("scripts/agent-conformance-adapter.mjs")
  ],
  { cwd: resolve(specs, "ietf"), encoding: "utf8" }
);

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exit(result.status ?? 1);

function parseArguments(args) {
  let specsDir = "../aep-specs";
  let outputDir = ".conformance/reports";
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    const value = args[index + 1];
    if (argument !== "--specs-dir" && argument !== "--output-dir") {
      throw new Error(`Unknown argument ${argument}`);
    }
    if (value === undefined) throw new Error(`${argument} requires a value`);
    if (argument === "--specs-dir") specsDir = value;
    else outputDir = value;
    index += 1;
  }
  return { outputDir, specsDir };
}
