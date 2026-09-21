import { commandPathFromInspect, parseProtectedResourceAuthorization } from "@aep-foundation/core";
import { createAepService } from "@aep-foundation/service";
import type {
  AepAuthenticatedPrincipal,
  AepIdempotentServiceOptions,
  AepService,
  AepServiceOptions
} from "@aep-foundation/service";

export const packageName = "@aep-foundation/hono";
export const AEP_HONO_WELL_KNOWN_PATH = "/.well-known/aep";
export const AEP_HONO_MEDIA_TYPE = "application/aep+json";

export interface HonoAepContext {
  json(body: unknown, status?: number, headers?: Record<string, string>): Response;
  req?: {
    header(name: string): string | undefined;
    json(): Promise<unknown>;
    raw?: Request;
  };
}

export function createHonoAepProtectedResourceHandler(
  input: HonoAepServiceInput,
  onAuthenticated?: (
    principal: AepAuthenticatedPrincipal,
    context: HonoAepContext
  ) => void | Promise<void>
): (context: HonoAepContext, next?: () => Promise<void>) => Promise<Response | void> {
  const service = resolveService(input);
  return async (context, next) => {
    const request = context.req?.raw;
    if (request === undefined)
      throw new TypeError("Hono protected-resource authentication requires req.raw.");
    const result = await service.authenticateProtectedResource({
      headers: request.headers,
      method: request.method,
      url: request.url
    });
    if (result.authenticated) {
      await onAuthenticated?.(result.principal, context);
      await next?.();
      return;
    }
    return context.json(result.response.body, result.response.status, {
      ...result.response.headers,
      "Content-Type": result.response.contentType
    });
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
    const clientAssertion = baselineClientAssertion(context.req?.header("Authorization"));
    const idempotencyKey = context.req?.header("Idempotency-Key");
    const body = command === "status" ? undefined : await requestBody(context);
    const commandOptions = idempotentOptions(clientAssertion, idempotencyKey);
    const result =
      command === "enroll"
        ? await service.enroll(body, commandOptions)
        : command === "status"
          ? await service.status({ clientAssertion })
          : command === "grant"
            ? await service.grant(body, commandOptions)
            : await service.revoke(body, commandOptions);

    return context.json(result.body, result.status, {
      ...result.headers,
      "Content-Type": result.contentType
    });
  };
}

function idempotentOptions(
  clientAssertion: string,
  idempotencyKey: string | undefined
): AepIdempotentServiceOptions {
  return {
    clientAssertion,
    idempotencyKey: idempotencyKey ?? ""
  };
}

/**
 * Reads the command request body.
 *
 * A body that is absent or not JSON resolves to `undefined` so the Service reports it as
 * `invalid_request`, rather than the parse rejection escaping as a framework error.
 */
async function requestBody(context: HonoAepContext): Promise<unknown> {
  try {
    return await context.req?.json();
  } catch {
    return undefined;
  }
}

/**
 * Reads the baseline client assertion from an `Authorization` field value.
 *
 * Scheme comparison is case-insensitive and the scheme may be followed by more than one
 * space. Anything that is not exactly one well-formed `AEP` credential yields an empty
 * assertion, which the Service reports as the common recognition failure rather than the
 * adapter guessing which of several presented credentials to evaluate.
 */
function baselineClientAssertion(authorization: string | undefined): string {
  if (authorization === undefined) {
    return "";
  }

  try {
    const parsed = parseProtectedResourceAuthorization(authorization);
    return parsed.scheme === "AEP" ? parsed.credentials : "";
  } catch {
    return "";
  }
}

function resolveService(input: HonoAepServiceInput): AepService {
  return "inspectDocument" in input ? input : createAepService(input);
}
