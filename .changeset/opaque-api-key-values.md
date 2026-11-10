---
"@aep-foundation/core": patch
"@aep-foundation/agent": patch
"@aep-foundation/service": patch
"@aep-foundation/conformance": patch
---

Accept complete opaque API-key header values, including Service-supplied authentication prefixes and internal spaces. Preserve the issued value and header without adding or removing a prefix, while rejecting unsafe field values.

Accept case-insensitive OAuth Bearer token types without changing access tokens.

Allow empty Basic usernames, passwords, and realms while requiring username and password fields to be present strings.

Verify API-key values through the configured credential handlers instead of rejecting Bearer or Basic prefixes as unsupported grant types. Reject requests that match multiple session credentials.
