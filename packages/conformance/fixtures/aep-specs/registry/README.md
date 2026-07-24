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
  claim-names/
    contact.address.primary.json
    contact.email.json
    contact.mobile.json
    person.birthdate.json
    person.first_name.json
    person.last_name.json
    person.username.json
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
performs repository-specific consistency checks. Claim Name checks also ensure
that the registry, Claims draft, and Claim Values schema contain the same
catalog and agree on every JSON value type.
