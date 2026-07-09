# Development

This repository uses pnpm workspaces and Turborepo. Prefer running package
checks through Turbo so changed workspace dependencies are rebuilt before the
target package runs.

## Full Verification

```sh
pnpm verify
```

`pnpm verify` runs formatting, typecheck, lint, tests, TypeDoc, builds, and
the example smoke matrix.

Run only the example smoke matrix after a build with:

```sh
pnpm smoke:examples
```

## Focused Package Verification

Use `verify:pkg` with a Turbo filter for focused work:

```sh
pnpm verify:pkg --filter=@aep-foundation/agent
pnpm verify:pkg --filter=@aep-foundation/conformance
```

This still honors task dependency edges from `turbo.json`, including `^build`
for dependency packages. Avoid using `pnpm --filter <package> test` after
editing a dependency package because that bypasses Turbo's dependency rebuild
graph and can exercise stale `dist` output.

For a single focused task, call Turbo directly:

```sh
pnpm turbo run test --filter=@aep-foundation/agent
pnpm turbo run typecheck --filter=@aep-foundation/service
```

## Coverage

Vitest writes coverage for each publishable package under that package's
`coverage/` directory. CI uploads the Node 22 coverage run to Codecov using
OIDC. The upload is intentionally non-blocking while the repository is being
bootstrapped in Codecov; use the uploaded GitHub coverage artifact as the local
fallback if Codecov is not ready yet.

## Publishing

Publishing is handled by the `release` workflow through Changesets. The workflow
uses npm Trusted Publishing, so configure each published package on npmjs.com
with this trusted publisher:

- Organization or user: `aep-foundation`
- Repository: `aep-node`
- Workflow filename: `release.yml`
- Allowed action: `npm publish`

The package manifests already set `publishConfig.access` to `public` and
`publishConfig.provenance` to `true`. Before the first release, run:

```sh
pnpm check-publish
```
