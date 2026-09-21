# @aep-foundation/hono

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

Thin Hono adapter for `@aep-foundation/service`.

On command routes, the baseline client assertion is read with the AEP scheme
rules: the scheme is case-insensitive and may be followed by more than one
space. A field carrying anything other than one well-formed `AEP` credential
presents no assertion, and the Service answers with its usual recognition
failure. A request body that is absent or not JSON reaches the Service as no
body, which it reports as `invalid_request`.

## Install

```sh
pnpm add @aep-foundation/service @aep-foundation/hono hono
```

## Mount AEP

```ts
import { registerHonoAepRoutes } from "@aep-foundation/hono";
import { Hono } from "hono";
import { service } from "./aep-service.js";

const app = new Hono();

registerHonoAepRoutes(app, service);
```

`registerHonoAepRoute()` registers only the Inspect route. Use
`registerHonoAepRoutes()` to register Inspect plus Enroll, Status, Grant, and
Revoke command routes from the Service Inspect metadata.

`createHonoAepProtectedResourceHandler(service)` authenticates `context.req.raw`
through the Service SDK.

Mount it as middleware before your protected route. Successful authentication
awaits Hono's `next()`; a failure returns the AEP challenge without continuing.
The optional second argument, `onAuthenticated(principal, context)`, runs before
`next()`. Use it to save the Agent identity and credential scopes for application
authorization, for example in a `WeakMap<object, AepAuthenticatedPrincipal>` keyed
by the context. If the callback rejects, Hono handles the error and does not run
the protected route. Calling the helper directly without `next` still returns
`undefined` on success. Do not authenticate a JWT again to recover its principal:
the first verification consumes its replay identifier.

See the [complete Hono example](../../../examples/aep-service-hono/README.md) for
protected routes, a Node listener, and a runnable Service configuration.
