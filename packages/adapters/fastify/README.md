# @aep-foundation/fastify

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection. Only the path and query of
the request target are used, resolved against the configured base URL, so a
request target in absolute form cannot move the protected-resource URI onto
another origin.

On command routes, the baseline client assertion is read with the AEP scheme
rules: the scheme is case-insensitive and may be followed by more than one
space. A field that repeats, or that carries anything other than one
well-formed `AEP` credential, presents no assertion, and the Service answers
with its usual recognition failure.

Thin Fastify adapter for `@aep-foundation/service`.

## Install

```sh
pnpm add @aep-foundation/service @aep-foundation/fastify fastify
```

## Mount AEP

```ts
import { createFastifyAepRoutesPlugin } from "@aep-foundation/fastify";
import Fastify from "fastify";
import { service } from "./aep-service.js";

const app = Fastify();

await app.register(async (aep) => {
  const parseJson = aep.getDefaultJsonParser("error", "error");
  aep.removeContentTypeParser("application/json");
  aep.addContentTypeParser<string>(
    ["application/json", "application/aep+json"],
    { parseAs: "string" },
    (request, body, done) => {
      return parseJson(request, body, (error, value) => done(null, error ? undefined : value));
    }
  );
  await aep.register(createFastifyAepRoutesPlugin(service));
});
await app.listen({ port: 3000 });
```

The parser is scoped to the AEP plugin. Invalid JSON reaches the Service as a
missing body: authentication runs first, then an authenticated malformed request
receives `400 application/problem+json` with `invalid_request`. Other application
routes retain their own parsing and error handling.

`createFastifyAepPlugin()` registers only the Inspect route. Use
`createFastifyAepRoutesPlugin()` to register Inspect plus Enroll, Status, Grant,
and Revoke command routes from the Service Inspect metadata.

`createFastifyAepProtectedResourceHandler(service, resourceBaseUrl)` delegates
authentication and challenge construction to the Service SDK.

The optional third argument is `onAuthenticated(principal, request)`. It runs
before the protected route and can save the Agent identity, credential identifier,
and scopes for application authorization. For example, store the principal in a
request-keyed `WeakMap<object, AepAuthenticatedPrincipal>` and read it in the route.
Do not authenticate the JWT a second time; that fails replay detection. If the
callback rejects, Fastify handles the error and does not run the protected route.

See the [complete Fastify example](../../../examples/aep-service-fastify/README.md)
for protected routes and a runnable Service configuration.
