# @aep-foundation/next

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

Thin Next.js adapter for `@aep-foundation/service`.

## Install

```sh
pnpm add @aep-foundation/service @aep-foundation/next next react react-dom
```

## Mount AEP

Create one Route Handler file for each advertised AEP route and export the
method returned by `createNextAepRoute()`:

```ts
import { createNextAepRoute } from "@aep-foundation/next";
import { service } from "../../../aep-service.js";

export const { POST } = createNextAepRoute(service, "enroll");
```

The Inspect and Status routes export `GET`; Enroll, Grant, and Revoke export
`POST`. Keep the shared `service` instance in an application module so every
Route Handler uses the same configuration and stores.

`createNextAepRoute()` defaults to an Inspect `GET` route. Pass `enroll`,
`status`, `grant`, or `revoke` to create the route handler object for command
route files.

`createNextAepProtectedResourceHandler(service, onAuthenticated)` authenticates
the Web `Request` through the Service SDK before application authorization.

See the [complete Next.js-style example](../../../examples/aep-service-next/README.md)
for all route handlers and a runnable local server.
