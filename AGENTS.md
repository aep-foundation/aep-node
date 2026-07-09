# AGENTS.md

Operating notes for working in this repository. If anything below conflicts with the source configs (`eslint.config.js`, `typedoc.json`, `tsconfig.base.json`, `turbo.json`, `.changeset/config.json`, `.prettierrc.json`), the configs win. Fix the drift instead of bypassing it.

## What This Repository Is

This repository is a pnpm and Turborepo monorepo for public Node.js SDK packages that implement the Agent Enrollment Protocol.

- `@aep-foundation/agent` contains Agent-side workflows.
- `@aep-foundation/conformance` contains schema and test-vector helpers used by SDKs and downstream implementations.
- `@aep-foundation/core` contains protocol constants, types, validators, signing helpers, and HTTP binding primitives.
- `@aep-foundation/platform` contains platform-managed Agent identity helpers.
- `@aep-foundation/service` contains Service-side workflows and extension registration hooks.
- `examples/*` contains runnable examples. Examples are not published packages.

## Repo Map

- `.changeset/` - pending version bumps and release configuration.
- `examples/*/` - runnable examples.
- `packages/*/` - publishable SDK packages.
- `packages/adapters/*/` - framework adapter packages when adapters are split out.
- `packages/extensions/*/` - AEP-owned extension packages when extension packages are split out.
- `scripts/` - repository-level development, verification, and publishing scripts.

Load-bearing root files: `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `turbo.json`, `eslint.config.js`, `.changeset/config.json`, `typedoc.json`, `.prettierrc.json`.

## Before Merging

Run the repository verification gate:

```sh
pnpm verify
```

For publish-surface changes, also run:

```sh
pnpm check-publish
```

Scope to one package with:

```sh
pnpm --filter @aep-foundation/core typecheck
```

## Conventions

- The package barrel, `src/index.ts`, is the public API surface.
- Anything exported from source but not re-exported from the package barrel is implementation detail and should not appear in public documentation.
- Do not use `any`, non-null assertions, or broad double casts unless the boundary is deliberate and documented by the surrounding code.
- Do not use `console.*` in `packages/**/src/**`. Package code should return values or throw typed errors; examples and scripts may log.
- Prefer small packages with explicit dependencies over hidden cross-package imports.
- Keep examples runnable and aligned with the public package APIs.
- Do not add historical notes to code comments. Comments and docs should describe the current behavior.
- Do not leave speculative `TODO` comments in shipped package code.

## Node Version Management

These settings serve different audiences:

- `package.json` `engines.node` is the supported runtime floor for package consumers.
- `.github/workflows/ci.yml` is the set of Node versions tested by continuous integration.
- `.nvmrc` is the local default for contributors.

The current runtime floor is Node.js 22.

## Package And Release Rules

- Published packages use `publishConfig.access: public` and `publishConfig.provenance: true`.
- Changes to `packages/**` require a Changeset unless the change is explicitly non-release-affecting.
- Release publication is handled through Changesets and npm provenance.
- Before publishing, run `pnpm check-publish` to verify package export maps and dry-run package contents.

## Documentation Rules

- Package READMEs should include working examples against the public package API.
- TSDoc should explain semantic behavior that the signature cannot express. Do not restate parameter names or return types.
- Use `{@link Symbol}` only for symbols that are exported from the package barrel and visible to TypeDoc.
- Keep protocol claims aligned with the AEP Internet-Draft set. When behavior is unclear, check the specification before implementing.

## Working As An Agent

- Read the files you are changing before editing.
- Check existing package patterns before introducing a new helper, dependency, or public shape.
- If a request affects protocol behavior, verify it against the current AEP specifications or ask for direction.
- Keep diffs narrow and avoid unrelated formatting churn.
- Run the real checks before reporting that work is complete.
- In the final report, list changed areas and the exact checks that passed or could not be run.
