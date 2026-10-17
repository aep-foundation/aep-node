---
"@aep-foundation/agent": patch
---

Revalidate public OpenAPI policies contradicted by validated AEP challenges. Preserve anonymous metadata retrieval and the existing authentication attempt, including when revalidation fails. Allow callers to request revalidation with the optional `openApiPolicy` and `inspectOpenApiPolicy` `revalidate` parameter.
