# @aep-foundation/next

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

Thin Next.js adapter for `@aep-foundation/service`.

On command routes, the baseline client assertion is read with the AEP scheme
rules: the scheme is case-insensitive and may be followed by more than one
space. A field carrying anything other than one well-formed `AEP` credential
presents no assertion, and the Service answers with its usual recognition
failure. A request body that is absent or not JSON reaches the Service as no
body, which it reports as `invalid_request`.

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
The callback receives `(request, principal)`. The principal contains the Agent
identity and, for session credentials, credential metadata and scopes. Check
application permissions there before returning the resource. Do not authenticate
the same JWT again: its replay identifier has already been consumed.

See the [complete Next.js-style example](../../../examples/aep-service-next/README.md)
for all route handlers and a runnable local server.
