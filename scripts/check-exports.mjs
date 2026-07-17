#!/usr/bin/env node

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packagesRoot = path.join(root, "packages");

async function pathExists(candidate) {
  try {
    await fs.access(candidate);
    return true;
  } catch {
    return false;
  }
}

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

function* walkExports(node, subpath, conditionChain) {
  if (typeof node === "string") {
    yield { subpath, condition: conditionChain.join(" > ") || "default", file: node };
    return;
  }

  if (node === null || typeof node !== "object") return;

  const keys = Object.keys(node);
  if (conditionChain.length > 0 && keys.includes("types") && keys[0] !== "types") {
    yield {
      subpath,
      condition: conditionChain.join(" > "),
      error: `'types' is not the first conditional key (found order: ${keys.join(", ")})`
    };
  }

  for (const key of keys) {
    yield* walkExports(node[key], subpath, [...conditionChain, key]);
  }
}

async function checkPackage({ dir, pkg }) {
  const errors = [];

  for (const field of ["main", "module", "types"]) {
    const value = pkg[field];
    if (typeof value !== "string") continue;
    if (!(await pathExists(path.join(dir, value)))) {
      errors.push(`${field}: "${value}" does not exist`);
    }
  }

  if (pkg.exports === undefined || pkg.exports === null) {
    errors.push("exports field is missing");
    return errors;
  }

  if (typeof pkg.exports === "string") {
    if (!(await pathExists(path.join(dir, pkg.exports)))) {
      errors.push(`exports: "${pkg.exports}" does not exist`);
    }
    return errors;
  }

  if (typeof pkg.exports !== "object") {
    errors.push("exports field must be a string or object");
    return errors;
  }

  for (const [subpath, subtree] of Object.entries(pkg.exports)) {
    for (const entry of walkExports(subtree, subpath, [])) {
      if (entry.error !== undefined) {
        errors.push(`exports["${entry.subpath}"]: ${entry.error}`);
        continue;
      }
      if (typeof entry.file !== "string") continue;
      if (!(await pathExists(path.join(dir, entry.file)))) {
        errors.push(
          `exports["${entry.subpath}"] (${entry.condition}): "${entry.file}" does not exist`
        );
      }
    }
  }

  return errors;
}

async function main() {
  const packages = await discoverPackages();
  if (packages.length === 0) {
    console.error("check-exports: no publishable @aep packages found under packages/");
    process.exit(1);
  }

  let failed = 0;
  console.log(`check-exports: ${packages.length} publishable packages\n`);

  for (const entry of packages) {
    process.stdout.write(`  ${entry.name} ... `);
    const errors = await checkPackage(entry);
    if (errors.length === 0) {
      console.log("OK");
      continue;
    }

    console.log("FAIL");
    failed += 1;
    for (const error of errors) {
      console.error(`    ${error}`);
    }
  }

  console.log("");
  if (failed > 0) {
    console.error(`check-exports: ${failed} package(s) failed`);
    process.exit(1);
  }

  console.log("check-exports: all packages OK");
}

main().catch((error) => {
  console.error("check-exports: unexpected error");
  console.error(error);
  process.exit(1);
});
