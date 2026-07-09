# @aep-foundation/fastify

Thin Fastify adapter for `@aep-foundation/service`.

`createFastifyAepPlugin()` registers only the Inspect route. Use
`createFastifyAepRoutesPlugin()` to register Inspect plus Enroll, Status, Grant,
and Revoke command routes from the Service Inspect metadata.
