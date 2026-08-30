import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  writeFile
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import prettier from "prettier";

const execute = promisify(execFile);
const canonicalRepository = "https://github.com/aep-foundation/aep-specs";
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const prettierConfig = (await prettier.resolveConfig(path.join(repoRoot, "package.json"))) ?? {};
const mode = parseMode(process.argv.slice(2));
const sourceRoot = await resolveSpecSource();
const source = await describeSpecSource(sourceRoot);
const targetRoot = path.join(repoRoot, "packages/conformance/fixtures/aep-specs");
const coreSchemaRoot = path.join(repoRoot, "packages/core/src/schemas");
const coreSchemaNames = ["claim-values.schema.json", "inspect-document.schema.json"];
const temporaryRoot = await mkdtemp(path.join(repoRoot, ".spec-artifacts-"));
const generatedRoot = path.join(temporaryRoot, "aep-specs");
const generatedCoreSchemaRoot = path.join(temporaryRoot, "core-schemas");

const artifactGroups = [
  {
    name: "examples",
    source: path.join(sourceRoot, "examples"),
    target: path.join(generatedRoot, "examples")
  },
  {
    name: "registry",
    source: path.join(sourceRoot, "registry"),
    target: path.join(generatedRoot, "registry")
  },
  {
    name: "schemas",
    source: path.join(sourceRoot, "schemas"),
    target: path.join(generatedRoot, "schemas")
  },
  {
    name: "test-vectors",
    source: path.join(sourceRoot, "test-vectors"),
    target: path.join(generatedRoot, "test-vectors")
  }
];

try {
  const artifacts = {};
  for (const group of artifactGroups) {
    artifacts[group.name] = await copyArtifactGroup(group.source, group.target);
  }

  await mkdir(generatedCoreSchemaRoot, { recursive: true });
  for (const name of coreSchemaNames) {
    await copyFormatted(
      path.join(sourceRoot, "schemas", name),
      path.join(generatedCoreSchemaRoot, name)
    );
  }

  const manifest = {
    source: `${canonicalRepository}/tree/${source.revision}/${source.directory}`,
    source_repository: canonicalRepository,
    source_revision: source.revision,
    source_directory: source.directory,
    artifact_revision: await artifactRevision(generatedRoot),
    generated_by: "scripts/sync-aep-spec-artifacts.mjs",
    artifacts
  };
  await writeJson(path.join(generatedRoot, "manifest.json"), manifest);

  const differences = [
    ...(await compareDirectories(generatedRoot, targetRoot, "fixtures")),
    ...(await compareDirectories(generatedCoreSchemaRoot, coreSchemaRoot, "core schemas", {
      files: coreSchemaNames
    }))
  ];

  if (mode === "check") {
    if (differences.length > 0) {
      process.stderr.write("AEP specification artifacts are not synchronized:\n");
      for (const difference of differences) process.stderr.write(`- ${difference}\n`);
      process.stderr.write("Run `pnpm sync:spec-artifacts` and commit the generated changes.\n");
      process.exitCode = 1;
    } else {
      process.stdout.write(
        `AEP specification artifacts match ${source.revision} (${manifest.artifact_revision}).\n`
      );
    }
  } else {
    if (differences.length > 0) {
      await rm(targetRoot, { recursive: true, force: true });
      await mkdir(path.dirname(targetRoot), { recursive: true });
      await rename(generatedRoot, targetRoot);

      await mkdir(coreSchemaRoot, { recursive: true });
      for (const name of coreSchemaNames) {
        await copyFile(path.join(generatedCoreSchemaRoot, name), path.join(coreSchemaRoot, name));
      }
    }

    const counts = Object.entries(artifacts)
      .map(([name, files]) => `${files.length} ${name} artifact(s)`)
      .join(", ");
    process.stdout.write(`${differences.length === 0 ? "Current" : "Synced"} ${counts}.\n`);
    process.stdout.write(`Source: ${manifest.source}\n`);
    process.stdout.write(`Artifact revision: ${manifest.artifact_revision}\n`);
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

function parseMode(args) {
  if (args.length !== 1 || (args[0] !== "--check" && args[0] !== "--write")) {
    throw new Error("Expected exactly one mode: --check or --write");
  }
  return args[0] === "--check" ? "check" : "write";
}

async function resolveSpecSource() {
  const requested = process.env.AEP_SPECS_DIR
    ? path.resolve(process.env.AEP_SPECS_DIR)
    : path.resolve(repoRoot, "../aep-specs");

  const candidates = [requested, path.join(requested, "ietf")];
  for (const candidate of candidates) {
    if (await hasSpecArtifactDirs(candidate)) return candidate;
  }

  throw new Error(
    `Could not find AEP spec artifacts. Set AEP_SPECS_DIR to an aep-specs checkout or ietf directory. Checked: ${candidates.join(", ")}`
  );
}

async function describeSpecSource(root) {
  const repositoryRoot = (
    await execute("git", ["-C", root, "rev-parse", "--show-toplevel"], { encoding: "utf8" })
  ).stdout.trim();
  const directory = normalizePath(path.relative(repositoryRoot, root));
  const sourceArtifactPaths = artifactPaths(directory);
  const status = (
    await execute(
      "git",
      [
        "-C",
        repositoryRoot,
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        ...sourceArtifactPaths
      ],
      { encoding: "utf8" }
    )
  ).stdout.trim();
  if (status !== "") {
    throw new Error(
      `AEP specification source contains uncommitted artifact changes:\n${status}\nCommit or restore them before synchronizing.`
    );
  }

  const revision = (
    await execute(
      "git",
      ["-C", repositoryRoot, "log", "-1", "--format=%H", "--", ...sourceArtifactPaths],
      { encoding: "utf8" }
    )
  ).stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(revision)) {
    throw new Error("Could not resolve the committed AEP specification artifact revision");
  }
  return { directory, revision };
}

function artifactPaths(directory) {
  return ["examples", "registry", "schemas", "test-vectors"].map((name) =>
    normalizePath(path.join(directory, name))
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
    const targetFile = path.join(target, relativeFile);
    await mkdir(path.dirname(targetFile), { recursive: true });
    await copyFormatted(path.join(source, relativeFile), targetFile);
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
      } else if (entry.isFile() && (entry.name.endsWith(".json") || entry.name.endsWith(".md"))) {
        files.push(path.relative(root, absolutePath));
      }
    }
  }
}

async function artifactRevision(root) {
  const hash = createHash("sha256");
  for (const relativeFile of await listArtifactFiles(root)) {
    hash.update(normalizePath(relativeFile));
    hash.update("\0");
    hash.update(await readFile(path.join(root, relativeFile)));
    hash.update("\0");
  }
  return `sha256:${hash.digest("hex")}`;
}

async function compareDirectories(expectedRoot, actualRoot, label, options = {}) {
  const expectedFiles = options.files ?? (await listArtifactFiles(expectedRoot));
  const actualFiles = options.files
    ? await existingFiles(actualRoot, options.files)
    : await listArtifactFilesOrEmpty(actualRoot);
  const differences = [];

  for (const relativeFile of expectedFiles) {
    if (!actualFiles.includes(relativeFile)) {
      differences.push(`${label}/${normalizePath(relativeFile)} is missing`);
      continue;
    }
    const expected = await readFile(path.join(expectedRoot, relativeFile));
    const actual = await readFile(path.join(actualRoot, relativeFile));
    if (!expected.equals(actual))
      differences.push(`${label}/${normalizePath(relativeFile)} differs`);
  }

  for (const relativeFile of actualFiles) {
    if (!expectedFiles.includes(relativeFile)) {
      differences.push(`${label}/${normalizePath(relativeFile)} is unexpected`);
    }
  }

  return differences;
}

async function existingFiles(root, files) {
  const existing = [];
  for (const relativeFile of files) {
    try {
      await readFile(path.join(root, relativeFile));
      existing.push(relativeFile);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  return existing;
}

async function listArtifactFilesOrEmpty(root) {
  try {
    return await listArtifactFiles(root);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
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
