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
import { service } from "./aep-service.js";

const app = express();

app.use(express.json());
registerExpressAepRoutes(app, service);
app.listen(3000);
```

`registerExpressAepRoute()` registers only the Inspect route. Use
`registerExpressAepRoutes()` to register Inspect plus Enroll, Status, Grant,
and Revoke command routes from the Service Inspect metadata.

`createExpressAepProtectedResourceHandler(service, resourceBaseUrl)` delegates
authentication and challenge construction to the Service SDK.
It forwards `Authorization` and `AEP-Authorization` unchanged for selection.

See the [complete Express example](../../../examples/aep-service-express/README.md)
for protected routes and a runnable Service configuration.
