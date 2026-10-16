# @aep-foundation/express

Thin Express adapter for `@aep-foundation/service`.

## Install

```sh
pnpm add @aep-foundation/service @aep-foundation/express express
```

## Mount AEP

```ts
import { registerExpressAepRoutes } from "@aep-foundation/express";
import express from "express";
import type { ErrorRequestHandler } from "express";
import { service } from "./aep-service.js";

const app = express();

const invalidAepJson: ErrorRequestHandler = (error: unknown, request, _response, next) => {
  if (error instanceof SyntaxError && "type" in error && error.type === "entity.parse.failed") {
    request.body = undefined;
    next();
  } else {
    next(error);
  }
};
app.use(
  ["/aep/enroll", "/aep/grant", "/aep/revoke"],
  express.json({ type: ["application/json", "application/aep+json"] }),
  invalidAepJson
);
registerExpressAepRoutes(app, service);
app.listen(3000);
```

The paths above use the default `/aep/` endpoint base. Match them to the Service's
`http.endpoint_base` if you configure another base. Install this parser before any
application-wide JSON parser. Invalid JSON reaches the Service as a missing body:
authentication runs first, then an authenticated malformed request receives
`400 application/problem+json` with `invalid_request`. Other application routes
retain their own parsing and error handling.

`registerExpressAepRoute()` registers only the Inspect route. Use
`registerExpressAepRoutes()` to register Inspect plus Enroll, Status, Grant,
and Revoke command routes from the Service Inspect metadata.

`createExpressAepProtectedResourceHandler(service, resourceBaseUrl)` delegates
authentication and challenge construction to the Service SDK.
It forwards `Authorization` and `AEP-Authorization` unchanged for selection.
Only the path and query of the request target are used, resolved against
`resourceBaseUrl`, so a request target in absolute form cannot move the
protected-resource URI onto another origin.

The optional third argument is `onAuthenticated(principal, request)`. It runs
before `next()` and can save the Agent identity, credential identifier, and scopes
for the application's authorization checks. For example, use a request-keyed
`WeakMap<object, AepAuthenticatedPrincipal>` and store the principal in the callback.
Read it in your protected route instead of authenticating the JWT again; a second
verification rejects the JWT as a replay. A rejected callback stops continuation
and reaches Express's error handler. The callback does not itself grant permission
to perform an application action.

On command routes, the baseline client assertion is read with the AEP scheme
rules: the scheme is case-insensitive and may be followed by more than one
space. A field that repeats, or that carries anything other than one
well-formed `AEP` credential, presents no assertion, and the Service answers
with its usual recognition failure.

See the [complete Express example](../../../examples/aep-service-express/README.md)
for protected routes and a runnable Service configuration.
