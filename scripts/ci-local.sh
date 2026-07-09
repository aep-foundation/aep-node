#!/usr/bin/env sh
set -eu

pnpm install --frozen-lockfile
pnpm verify
pnpm check-publish
