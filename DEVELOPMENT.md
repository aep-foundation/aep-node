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
