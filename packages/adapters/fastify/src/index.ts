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

export const packageName = "@aep-foundation/fastify";
export const AEP_FASTIFY_WELL_KNOWN_PATH = "/.well-known/aep";
export const AEP_FASTIFY_MEDIA_TYPE = "application/aep+json";
export const AEP_FASTIFY_PROBLEM_MEDIA_TYPE = "application/problem+json";

export interface FastifyAepReply {
  header?(name: string, value: string): FastifyAepReply;
  send(body: unknown): unknown;
  status?(code: number): FastifyAepReply;
  type(contentType: string): FastifyAepReply;
}

export interface FastifyAepRequest {
  body?: unknown;
  headers?: Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
}

export function createFastifyAepProtectedResourceHandler(
  input: FastifyAepServiceInput,
  resourceBaseUrl: string | URL,
  onAuthenticated?: (
    principal: AepAuthenticatedPrincipal,
    request: FastifyAepRequest
  ) => void | Promise<void>
): (request: FastifyAepRequest, reply: FastifyAepReply) => Promise<unknown> {
  const service = resolveService(input);
  return async (request, reply) => {
    const result = await service.authenticateProtectedResource({
      headers: request.headers ?? {},
      method: request.method ?? "GET",
      url: protectedResourceUrl(request.url ?? "/", resourceBaseUrl)
    });
    if (result.authenticated) {
      await onAuthenticated?.(result.principal, request);
      return;
    }
    for (const [name, value] of Object.entries(result.response.headers ?? {}))
      reply.header?.(name, value);
    reply.status?.(result.response.status);
    return reply.type(result.response.contentType).send(result.response.body);
  };
}

export type FastifyAepHandler = (request: FastifyAepRequest, reply: FastifyAepReply) => unknown;

export interface FastifyAepInspectInstance {
  get(path: string, handler: FastifyAepHandler): unknown;
}

export interface FastifyAepInstance extends FastifyAepInspectInstance {
  post(path: string, handler: FastifyAepHandler): unknown;
}

export type FastifyAepInspectPlugin = (fastify: FastifyAepInspectInstance) => Promise<void>;
export type FastifyAepPlugin = (fastify: FastifyAepInstance) => Promise<void>;
export type FastifyAepServiceInput = AepService | AepServiceOptions;

export interface FastifyAepRouteHandlers {
  enroll: FastifyAepHandler;
  grant: FastifyAepHandler;
  inspect: FastifyAepHandler;
  revoke: FastifyAepHandler;
  status: FastifyAepHandler;
}

export function createFastifyAepHandler(input: FastifyAepServiceInput): FastifyAepHandler {
  const service = resolveService(input);

  return (request, reply) => {
    if (request.method !== undefined && request.method !== "GET") {
      reply.header?.("Allow", "GET");
      reply.status?.(405);
      return reply.type(AEP_FASTIFY_PROBLEM_MEDIA_TYPE).send(
        createProblemDetails({
          code: "invalid_request",
          detail: "AEP Inspect only supports GET requests.",
          status: 405,
          title: "Method Not Allowed"
        })
      );
    }

    reply.status?.(200);
    return reply.type(AEP_FASTIFY_MEDIA_TYPE).send(service.inspectDocument());
  };
}

export function createFastifyAepHandlers(input: FastifyAepServiceInput): FastifyAepRouteHandlers {
  const service = resolveService(input);

  return {
    enroll: createFastifyCommandHandler(service, "enroll"),
    grant: createFastifyCommandHandler(service, "grant"),
    inspect: createFastifyAepHandler(service),
    revoke: createFastifyCommandHandler(service, "revoke"),
    status: createFastifyCommandHandler(service, "status")
  };
}

export function createFastifyAepPlugin(
  input: FastifyAepServiceInput,
  path = AEP_FASTIFY_WELL_KNOWN_PATH
): FastifyAepInspectPlugin {
  return (fastify) => {
    fastify.get(path, createFastifyAepHandler(input));
    return Promise.resolve();
  };
}

export function createFastifyAepRoutesPlugin(
  input: FastifyAepServiceInput,
  inspectPath = AEP_FASTIFY_WELL_KNOWN_PATH
): FastifyAepPlugin {
  return (fastify) => {
    const service = resolveService(input);
    const handlers = createFastifyAepHandlers(service);
    const inspect = service.inspectDocument();

    fastify.get(inspectPath, handlers.inspect);
    fastify.post(commandPathFromInspect(inspect, "enroll"), handlers.enroll);
    fastify.get(commandPathFromInspect(inspect, "status"), handlers.status);
    fastify.post(commandPathFromInspect(inspect, "grant"), handlers.grant);
    fastify.post(commandPathFromInspect(inspect, "revoke"), handlers.revoke);
    return Promise.resolve();
  };
}

function createFastifyCommandHandler(
  service: AepService,
  command: "enroll" | "grant" | "revoke" | "status"
): FastifyAepHandler {
  return async (request, reply) => {
    const clientAssertion = baselineClientAssertion(request.headers?.["authorization"]);
    const idempotencyKey = singleFieldValue(request.headers?.["idempotency-key"]);
    const commandOptions = idempotentOptions(clientAssertion, idempotencyKey);
    const result =
      command === "enroll"
        ? await service.enroll(request.body, commandOptions)
        : command === "status"
          ? await service.status({ clientAssertion })
          : command === "grant"
            ? await service.grant(request.body, commandOptions)
            : await service.revoke(request.body, commandOptions);

    reply.status?.(result.status);
    for (const [name, value] of Object.entries(result.headers ?? {})) reply.header?.(name, value);
    return reply.type(result.contentType).send(result.body);
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

function resolveService(input: FastifyAepServiceInput): AepService {
  return "inspectDocument" in input ? input : createAepService(input);
}
