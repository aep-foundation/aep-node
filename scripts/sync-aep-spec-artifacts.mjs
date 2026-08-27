import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import prettier from "prettier";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const prettierConfig = (await prettier.resolveConfig(path.join(repoRoot, "package.json"))) ?? {};
const sourceRoot = await resolveSpecSource();
const targetRoot = path.join(repoRoot, "packages/conformance/fixtures/aep-specs");
const coreSchemaRoot = path.join(repoRoot, "packages/core/src/schemas");
const coreSchemaNames = ["claim-values.schema.json", "inspect-document.schema.json"];

const artifactGroups = [
  {
    name: "examples",
    source: path.join(sourceRoot, "examples"),
    target: path.join(targetRoot, "examples")
  },
  {
    name: "registry",
    source: path.join(sourceRoot, "registry"),
    target: path.join(targetRoot, "registry")
  },
  {
    name: "schemas",
    source: path.join(sourceRoot, "schemas"),
    target: path.join(targetRoot, "schemas")
  },
  {
    name: "test-vectors",
    source: path.join(sourceRoot, "test-vectors"),
    target: path.join(targetRoot, "test-vectors")
  }
];

await rm(targetRoot, { recursive: true, force: true });
await mkdir(targetRoot, { recursive: true });

const manifest = {
  source: normalizePath(path.relative(repoRoot, sourceRoot)),
  generated_by: "scripts/sync-aep-spec-artifacts.mjs",
  artifacts: {}
};

for (const group of artifactGroups) {
  const copied = await copyArtifactGroup(group.source, group.target);
  manifest.artifacts[group.name] = copied;
}

await mkdir(coreSchemaRoot, { recursive: true });
for (const name of coreSchemaNames) {
  await copyFormatted(path.join(sourceRoot, "schemas", name), path.join(coreSchemaRoot, name));
}

await writeJson(path.join(targetRoot, "manifest.json"), manifest);

const counts = Object.entries(manifest.artifacts)
  .map(([name, files]) => `${files.length} ${name} artifact(s)`)
  .join(", ");

console.log(`Synced ${counts}.`);
console.log(`Source: ${manifest.source}`);
console.log(`Target: ${normalizePath(path.relative(repoRoot, targetRoot))}`);

async function resolveSpecSource() {
  const requested = process.env.AEP_SPECS_DIR
    ? path.resolve(process.env.AEP_SPECS_DIR)
    : path.resolve(repoRoot, "../aep-specs");

  const candidates = [requested, path.join(requested, "ietf")];

  for (const candidate of candidates) {
    if (await hasSpecArtifactDirs(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    `Could not find AEP spec artifacts. Set AEP_SPECS_DIR to an aep-specs checkout or ietf directory. Checked: ${candidates.join(", ")}`
  );
}

async function hasSpecArtifactDirs(candidate) {
  try {
    const schemas = await readdir(path.join(candidate, "schemas"));
    const vectors = await readdir(path.join(candidate, "test-vectors"));
    return schemas.length > 0 && vectors.length > 0;
  } catch {
    return false;
  }
}

async function copyArtifactGroup(source, target) {
  const relativeFiles = await listArtifactFiles(source);

  await mkdir(target, { recursive: true });

  for (const relativeFile of relativeFiles) {
    const sourceFile = path.join(source, relativeFile);
    const targetFile = path.join(target, relativeFile);

    await mkdir(path.dirname(targetFile), { recursive: true });
    await copyFormatted(sourceFile, targetFile);
  }

  return relativeFiles.map(normalizePath);
}

async function listArtifactFiles(root) {
  const files = [];

  await visit(root);

  return files.sort();

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });

    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        await visit(absolutePath);
        continue;
      }

      if (entry.isFile() && (entry.name.endsWith(".json") || entry.name.endsWith(".md"))) {
        files.push(path.relative(root, absolutePath));
      }
    }
  }
}

async function writeJson(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function copyFormatted(sourceFile, targetFile) {
  const text = await readFile(sourceFile, "utf8");
  const parser = sourceFile.endsWith(".json") ? "json" : "markdown";
  const formatted = await prettier.format(text, { ...prettierConfig, parser });

  await writeFile(targetFile, formatted);
}

function normalizePath(value) {
  return value.split(path.sep).join("/");
}
