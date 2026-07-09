import { commandPathFromInspect } from "@aep-foundation/core";
import { createAepService } from "@aep-foundation/service";
import type {
  AepAuthenticatedServiceOptions,
  AepService,
  AepServiceOptions
} from "@aep-foundation/service";

export const packageName = "@aep-foundation/express";
export const AEP_EXPRESS_WELL_KNOWN_PATH = "/.well-known/aep";
export const AEP_EXPRESS_MEDIA_TYPE = "application/aep+json";

export interface ExpressAepRequest {
  body?: unknown;
  get?(field: string): string | undefined;
  header?(field: string): string | undefined;
  headers?: Record<string, string | string[] | undefined>;
  method?: string;
}

export interface ExpressAepResponse {
  json(body: unknown): unknown;
  set?(field: string, value: string): unknown;
  status(code: number): ExpressAepResponse;
  type?(contentType: string): ExpressAepResponse;
}

export type ExpressAepNext = () => void;
export type ExpressAepHandler = (
  request: ExpressAepRequest,
  response: ExpressAepResponse,
  next?: ExpressAepNext
) => unknown;

export type ExpressAepServiceInput = AepService | AepServiceOptions;

export interface ExpressAepInspectRouterLike {
  get(path: string, handler: ExpressAepHandler): unknown;
}

export interface ExpressAepRouterLike extends ExpressAepInspectRouterLike {
  post(path: string, handler: ExpressAepHandler): unknown;
}

export interface ExpressAepRouteHandlers {
  enroll: ExpressAepHandler;
  grant: ExpressAepHandler;
  inspect: ExpressAepHandler;
  revoke: ExpressAepHandler;
  status: ExpressAepHandler;
}

export function createExpressAepHandler(input: ExpressAepServiceInput): ExpressAepHandler {
  const service = resolveService(input);

  return (request, response) => {
    if (request.method !== undefined && request.method !== "GET") {
      response.set?.("Allow", "GET");
      return response.status(405).json({
        detail: "AEP Inspect only supports GET requests.",
        status: 405,
        title: "Method Not Allowed"
      });
    }

    response.type?.(AEP_EXPRESS_MEDIA_TYPE);
    return response.status(200).json(service.inspectDocument());
  };
}

export function createExpressAepHandlers(input: ExpressAepServiceInput): ExpressAepRouteHandlers {
  const service = resolveService(input);

  return {
    enroll: createExpressCommandHandler(service, "enroll"),
    grant: createExpressCommandHandler(service, "grant"),
    inspect: createExpressAepHandler(service),
    revoke: createExpressCommandHandler(service, "revoke"),
    status: createExpressCommandHandler(service, "status")
  };
}

export function registerExpressAepRoute(
  router: ExpressAepInspectRouterLike,
  input: ExpressAepServiceInput,
  path = AEP_EXPRESS_WELL_KNOWN_PATH
): ExpressAepInspectRouterLike {
  router.get(path, createExpressAepHandler(input));
  return router;
}

export function registerExpressAepRoutes(
  router: ExpressAepRouterLike,
  input: ExpressAepServiceInput,
  inspectPath = AEP_EXPRESS_WELL_KNOWN_PATH
): ExpressAepRouterLike {
  const service = resolveService(input);
  const handlers = createExpressAepHandlers(service);
  const inspect = service.inspectDocument();

  router.get(inspectPath, handlers.inspect);
  router.post(commandPathFromInspect(inspect, "enroll"), handlers.enroll);
  router.get(commandPathFromInspect(inspect, "status"), handlers.status);
  router.post(commandPathFromInspect(inspect, "grant"), handlers.grant);
  router.post(commandPathFromInspect(inspect, "revoke"), handlers.revoke);
  return router;
}

function createExpressCommandHandler(
  service: AepService,
  command: "enroll" | "grant" | "revoke" | "status"
): ExpressAepHandler {
  return async (request, response) => {
    const clientAssertion = authorizationAssertion(request);
    const idempotencyKey = idempotencyKeyHeader(request);
    const commandOptions = authenticatedOptions(clientAssertion, idempotencyKey);
    const result =
      command === "enroll"
        ? await service.enroll(request.body, commandOptions)
        : command === "status"
          ? await service.status({ clientAssertion })
          : command === "grant"
            ? await service.grant(request.body, commandOptions)
            : await service.revoke(request.body, commandOptions);

    response.type?.(result.contentType);
    return response.status(result.status).json(result.body);
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

function authorizationAssertion(request: ExpressAepRequest): string {
  const authorization =
    request.get?.("Authorization") ??
    request.header?.("Authorization") ??
    headerValue(request.headers, "authorization");

  return parseAepAuthorization(authorization);
}

function idempotencyKeyHeader(request: ExpressAepRequest): string | undefined {
  return (
    request.get?.("Idempotency-Key") ??
    request.header?.("Idempotency-Key") ??
    headerValue(request.headers, "idempotency-key")
  );
}

function headerValue(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string
): string | undefined {
  const value = headers?.[name] ?? headers?.[name.toLowerCase()];

  return Array.isArray(value) ? value[0] : value;
}

function parseAepAuthorization(authorization: string | undefined): string {
  const prefix = "AEP ";

  if (authorization?.startsWith(prefix)) {
    return authorization.slice(prefix.length);
  }

  return "";
}

function resolveService(input: ExpressAepServiceInput): AepService {
  return "inspectDocument" in input ? input : createAepService(input);
}
