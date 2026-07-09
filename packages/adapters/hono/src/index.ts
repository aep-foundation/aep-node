import { commandPathFromInspect } from "@aep-foundation/core";
import { createAepService } from "@aep-foundation/service";
import type {
  AepAuthenticatedServiceOptions,
  AepService,
  AepServiceOptions
} from "@aep-foundation/service";

export const packageName = "@aep-foundation/hono";
export const AEP_HONO_WELL_KNOWN_PATH = "/.well-known/aep";
export const AEP_HONO_MEDIA_TYPE = "application/aep+json";

export interface HonoAepContext {
  json(body: unknown, status?: number, headers?: Record<string, string>): unknown;
  req?: {
    header(name: string): string | undefined;
    json(): Promise<unknown>;
  };
}

export type HonoAepHandler = (context: HonoAepContext) => unknown;

export interface HonoAepInspectAppLike {
  get(path: string, handler: HonoAepHandler): unknown;
}

export interface HonoAepAppLike extends HonoAepInspectAppLike {
  post(path: string, handler: HonoAepHandler): unknown;
}

export type HonoAepServiceInput = AepService | AepServiceOptions;

export interface HonoAepRouteHandlers {
  enroll: HonoAepHandler;
  grant: HonoAepHandler;
  inspect: HonoAepHandler;
  revoke: HonoAepHandler;
  status: HonoAepHandler;
}

export function createHonoAepHandler(input: HonoAepServiceInput): HonoAepHandler {
  const service = resolveService(input);

  return (context) =>
    context.json(service.inspectDocument(), 200, {
      "Content-Type": AEP_HONO_MEDIA_TYPE
    });
}

export function createHonoAepHandlers(input: HonoAepServiceInput): HonoAepRouteHandlers {
  const service = resolveService(input);

  return {
    enroll: createHonoCommandHandler(service, "enroll"),
    grant: createHonoCommandHandler(service, "grant"),
    inspect: createHonoAepHandler(service),
    revoke: createHonoCommandHandler(service, "revoke"),
    status: createHonoCommandHandler(service, "status")
  };
}

export function registerHonoAepRoute(
  app: HonoAepInspectAppLike,
  input: HonoAepServiceInput,
  path = AEP_HONO_WELL_KNOWN_PATH
): HonoAepInspectAppLike {
  app.get(path, createHonoAepHandler(input));
  return app;
}

export function registerHonoAepRoutes(
  app: HonoAepAppLike,
  input: HonoAepServiceInput,
  inspectPath = AEP_HONO_WELL_KNOWN_PATH
): HonoAepAppLike {
  const service = resolveService(input);
  const handlers = createHonoAepHandlers(service);
  const inspect = service.inspectDocument();

  app.get(inspectPath, handlers.inspect);
  app.post(commandPathFromInspect(inspect, "enroll"), handlers.enroll);
  app.get(commandPathFromInspect(inspect, "status"), handlers.status);
  app.post(commandPathFromInspect(inspect, "grant"), handlers.grant);
  app.post(commandPathFromInspect(inspect, "revoke"), handlers.revoke);
  return app;
}

function createHonoCommandHandler(
  service: AepService,
  command: "enroll" | "grant" | "revoke" | "status"
): HonoAepHandler {
  return async (context) => {
    const clientAssertion = parseAepAuthorization(context.req?.header("Authorization"));
    const idempotencyKey = context.req?.header("Idempotency-Key");
    const body = command === "status" ? undefined : await context.req?.json();
    const commandOptions = authenticatedOptions(clientAssertion, idempotencyKey);
    const result =
      command === "enroll"
        ? await service.enroll(body, commandOptions)
        : command === "status"
          ? await service.status({ clientAssertion })
          : command === "grant"
            ? await service.grant(body, commandOptions)
            : await service.revoke(body, commandOptions);

    return context.json(result.body, result.status, {
      "Content-Type": result.contentType
    });
  };
}

function authenticatedOptions(
  clientAssertion: string,
  idempotencyKey: string | undefined
): AepAuthenticatedServiceOptions {
  return {
    clientAssertion,
    ...(idempotencyKey === undefined ? {} : { idempotencyKey })
  };
}

function parseAepAuthorization(authorization: string | undefined): string {
  const prefix = "AEP ";

  if (authorization?.startsWith(prefix)) {
    return authorization.slice(prefix.length);
  }

  return "";
}

function resolveService(input: HonoAepServiceInput): AepService {
  return "inspectDocument" in input ? input : createAepService(input);
}
