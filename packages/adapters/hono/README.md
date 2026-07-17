# @aep-foundation/hono

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

Thin Hono adapter for `@aep-foundation/service`.

`registerHonoAepRoute()` registers only the Inspect route. Use
`registerHonoAepRoutes()` to register Inspect plus Enroll, Status, Grant, and
Revoke command routes from the Service Inspect metadata.

`createHonoAepProtectedResourceHandler(service)` authenticates `context.req.raw`
through the Service SDK.
