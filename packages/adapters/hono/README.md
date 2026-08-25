# @aep-foundation/hono

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

Thin Hono adapter for `@aep-foundation/service`.

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

See the [complete Hono example](../../../examples/aep-service-hono/README.md) for
protected routes, a Node listener, and a runnable Service configuration.
