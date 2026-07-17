# @aep-foundation/next

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

Thin Next.js adapter for `@aep-foundation/service`.

`createNextAepRoute()` defaults to an Inspect `GET` route. Pass `enroll`,
`status`, `grant`, or `revoke` to create the route handler object for command
route files.

`createNextAepProtectedResourceHandler(service, onAuthenticated)` authenticates
the Web `Request` through the Service SDK before application authorization.
