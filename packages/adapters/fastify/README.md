# @aep-foundation/fastify

Protected-resource handlers forward `Authorization` and `AEP-Authorization`
unchanged to the Service SDK for carrier selection.

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

await app.register(createFastifyAepRoutesPlugin(service));
await app.listen({ port: 3000 });
```

`createFastifyAepPlugin()` registers only the Inspect route. Use
`createFastifyAepRoutesPlugin()` to register Inspect plus Enroll, Status, Grant,
and Revoke command routes from the Service Inspect metadata.

`createFastifyAepProtectedResourceHandler(service, resourceBaseUrl)` delegates
authentication and challenge construction to the Service SDK.

See the [complete Fastify example](../../../examples/aep-service-fastify/README.md)
for protected routes and a runnable Service configuration.
