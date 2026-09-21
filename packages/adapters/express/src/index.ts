import {
  commandPathFromInspect,
  createProblemDetails,
  parseProtectedResourceAuthorization
} from "@aep-foundation/core";
import { createAepService } from "@aep-foundation/service";
import type {
  AepAuthenticatedPrincipal,
  AepIdempotentServiceOptions,
  AepService,
  AepServiceOptions
} from "@aep-foundation/service";

export const packageName = "@aep-foundation/express";
export const AEP_EXPRESS_WELL_KNOWN_PATH = "/.well-known/aep";
export const AEP_EXPRESS_MEDIA_TYPE = "application/aep+json";
export const AEP_EXPRESS_PROBLEM_MEDIA_TYPE = "application/problem+json";

export interface ExpressAepRequest {
  body?: unknown;
  get?(field: string): string | undefined;
  header?(field: string): string | undefined;
  headers?: Record<string, string | string[] | undefined>;
  method?: string;
  originalUrl?: string;
  protocol?: string;
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
      response.type?.(AEP_EXPRESS_PROBLEM_MEDIA_TYPE);
      return response.status(405).json(
        createProblemDetails({
          code: "invalid_request",
          detail: "AEP Inspect only supports GET requests.",
          status: 405,
          title: "Method Not Allowed"
        })
      );
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

export function createExpressAepProtectedResourceHandler(
  input: ExpressAepServiceInput,
  resourceBaseUrl: string | URL,
  onAuthenticated?: (
    principal: AepAuthenticatedPrincipal,
    request: ExpressAepRequest
  ) => void | Promise<void>
): ExpressAepHandler {
  const service = resolveService(input);
  return async (request, response, next) => {
    const result = await service.authenticateProtectedResource({
      headers: request.headers ?? {},
      method: request.method ?? "GET",
      url: protectedResourceUrl(request.originalUrl ?? "/", resourceBaseUrl)
    });
    if (result.authenticated) {
      await onAuthenticated?.(result.principal, request);
      return next?.();
    }
    response.type?.(result.response.contentType);
    for (const [name, value] of Object.entries(result.response.headers ?? {}))
      response.set?.(name, value);
    return response.status(result.response.status).json(result.response.body);
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
    const commandOptions = idempotentOptions(clientAssertion, idempotencyKey);
    const result =
      command === "enroll"
        ? await service.enroll(request.body, commandOptions)
        : command === "status"
          ? await service.status({ clientAssertion })
          : command === "grant"
            ? await service.grant(request.body, commandOptions)
            : await service.revoke(request.body, commandOptions);

    response.type?.(result.contentType);
    for (const [name, value] of Object.entries(result.headers ?? {})) response.set?.(name, value);
    return response.status(result.status).json(result.body);
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
 * Resolves the protected-resource target.
 *
 * A request target can arrive in absolute form, so only its path and query identify the
 * resource on this Service. Everything else is discarded and the result is resolved against
 * the configured base URL, so a caller cannot move the `resource` an assertion binds to onto
 * another origin.
 */
function protectedResourceUrl(target: string, resourceBaseUrl: string | URL): URL {
  // A leading // in an HTTP request target is a path, not a replacement authority.
  const pathOnly = new URL(target.startsWith("/") ? `http://aep.invalid${target}` : target);
  const resource = new URL(resourceBaseUrl);
  resource.pathname = pathOnly.pathname;
  resource.search = pathOnly.search;
  resource.hash = "";
  return resource;
}

function authorizationAssertion(request: ExpressAepRequest): string {
  const raw = request.headers?.["authorization"] ?? request.headers?.["Authorization"];
  const authorization = raw ?? request.get?.("Authorization") ?? request.header?.("Authorization");

  return baselineClientAssertion(authorization);
}

function idempotencyKeyHeader(request: ExpressAepRequest): string | undefined {
  const raw = request.headers?.["idempotency-key"] ?? request.headers?.["Idempotency-Key"];
  const value = raw ?? request.get?.("Idempotency-Key") ?? request.header?.("Idempotency-Key");

  return singleFieldValue(value);
}

/**
 * Reads the baseline client assertion from an `Authorization` field value.
 *
 * Scheme comparison is case-insensitive and the scheme may be followed by more than one
 * space. Anything that is not exactly one well-formed `AEP` credential yields an empty
 * assertion, which the Service reports as the common recognition failure rather than the
 * adapter guessing which of several presented credentials to evaluate.
 */
function baselineClientAssertion(authorization: string | string[] | undefined): string {
  const value = singleFieldValue(authorization);

  if (value === undefined) {
    return "";
  }

  try {
    const parsed = parseProtectedResourceAuthorization(value);
    return parsed.scheme === "AEP" ? parsed.credentials : "";
  } catch {
    return "";
  }
}

/** A repeated field line is ambiguous, so it resolves to no value rather than to its first. */
function singleFieldValue(value: string | string[] | undefined): string | undefined {
  if (!Array.isArray(value)) {
    return value;
  }

  return value.length === 1 ? value[0] : undefined;
}

function resolveService(input: ExpressAepServiceInput): AepService {
  return "inspectDocument" in input ? input : createAepService(input);
}
