# AEP Repository Registry

This directory contains repository-local, machine-readable registry entries for
AEP protocol identifiers.

These entries are governance support material. They do not replace IANA
registries once IANA registries exist.

## Layout

```text
registry/
  registry-entry.schema.json
  authentication-methods/
    aep-jwt.json
  extensions/
    openapi-authentication.json
  http-fields/
    aep-authorization.json
  grant-types/
    oauth-bearer.json
    api-key.json
    basic.json
  identity-methods/
    did-web.json
```

## Validation

Run:

```sh
make -C ietf check-registry
```

The checker validates each entry against `registry-entry.schema.json` and
performs repository-specific consistency checks.
