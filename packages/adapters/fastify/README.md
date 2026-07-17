# @aep-foundation/fastify

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

Thin Fastify adapter for `@aep-foundation/service`.

`createFastifyAepPlugin()` registers only the Inspect route. Use
`createFastifyAepRoutesPlugin()` to register Inspect plus Enroll, Status, Grant,
and Revoke command routes from the Service Inspect metadata.

`createFastifyAepProtectedResourceHandler(service, resourceBaseUrl)` delegates
authentication and challenge construction to the Service SDK.
