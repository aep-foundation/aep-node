#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileP = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packagesRoot = path.join(root, "packages");

const requiredTarballEntries = ["dist/", "README.md", "LICENSE"];
const forbiddenPatterns = [/^src\//u, /^test\//u, /\.test\.[mc]?[jt]s$/u, /\.spec\.[mc]?[jt]s$/u];

async function walkPackageJsonFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walkPackageJsonFiles(full)));
      continue;
    }
    if (entry.isFile() && entry.name === "package.json") {
      files.push(full);
    }
  }

  return files;
}

async function discoverPackages() {
  const files = await walkPackageJsonFiles(packagesRoot);
  const packages = [];

  for (const pkgPath of files) {
    const dir = path.dirname(pkgPath);
    const pkg = JSON.parse(await fs.readFile(pkgPath, "utf8"));
    if (pkg.private === true) continue;
    if (typeof pkg.name !== "string" || !pkg.name.startsWith("@aep-foundation/")) continue;
    packages.push({ name: pkg.name, dir, pkg });
  }

  return packages.sort((a, b) => a.name.localeCompare(b.name));
}

async function dryRunPack(dir) {
  const { stdout } = await execFileP("pnpm", ["pack", "--dry-run", "--json"], { cwd: dir });
  const parsed = JSON.parse(stdout);
  const record = Array.isArray(parsed) ? parsed[0] : parsed;
  const files = Array.isArray(record?.files) ? record.files : [];
  const entries = files.map((file) => file.path);
  const size = await sumEntrySizes(dir, entries);
  return { entries, size };
}

async function sumEntrySizes(dir, entries) {
  let size = 0;
  for (const entry of entries) {
    const stat = await fs.stat(path.join(dir, entry));
    if (stat.isFile()) {
      size += stat.size;
    }
  }
  return size;
}

function checkEntries(entries) {
  const missing = requiredTarballEntries.filter((required) =>
    required.endsWith("/")
      ? !entries.some((entry) => entry.startsWith(required))
      : !entries.includes(required)
  );
  const forbidden = entries.filter((entry) =>
    forbiddenPatterns.some((pattern) => pattern.test(entry))
  );
  return { missing, forbidden };
}

function formatBytes(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

async function main() {
  const packages = await discoverPackages();
  if (packages.length === 0) {
    console.error("verify-publish: no publishable @aep packages found under packages/");
    process.exit(1);
  }

  let failed = 0;
  console.log(`verify-publish: ${packages.length} publishable packages\n`);

  for (const { name, dir } of packages) {
    process.stdout.write(`  ${name} ... `);

    let result;
    try {
      result = await dryRunPack(dir);
    } catch (error) {
      console.log("FAIL");
      console.error(
        `    pnpm pack failed: ${error instanceof Error ? error.message : String(error)}`
      );
      failed += 1;
      continue;
    }

    const { missing, forbidden } = checkEntries(result.entries);
    if (missing.length > 0) {
      console.log("FAIL");
      console.error(`    missing required entries: ${missing.join(", ")}`);
      failed += 1;
      continue;
    }

    if (forbidden.length > 0) {
      console.log("FAIL");
      console.error(`    forbidden entries found in tarball: ${forbidden.join(", ")}`);
      failed += 1;
      continue;
    }

    console.log(`OK (${result.entries.length} files, ${formatBytes(result.size)})`);
  }

  console.log("");
  if (failed > 0) {
    console.error(`verify-publish: ${failed} package(s) failed`);
    process.exit(1);
  }

  console.log("verify-publish: all packages OK");
}

main().catch((error) => {
  console.error("verify-publish: unexpected error");
  console.error(error);
  process.exit(1);
});
