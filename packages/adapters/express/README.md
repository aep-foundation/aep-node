# @aep-foundation/express

Thin Express adapter for `@aep-foundation/service`.

`registerExpressAepRoute()` registers only the Inspect route. Use
`registerExpressAepRoutes()` to register Inspect plus Enroll, Status, Grant,
and Revoke command routes from the Service Inspect metadata.

`createExpressAepProtectedResourceHandler(service, resourceBaseUrl)` delegates
authentication and challenge construction to the Service SDK.
It forwards `Authorization` and `AEP-Authorization` unchanged for selection.
