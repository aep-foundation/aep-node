import { commandPathFromInspect } from "@aep-foundation/core";
import { createAepService } from "@aep-foundation/service";
import type {
  AepIdempotentServiceOptions,
  AepService,
  AepServiceOptions
} from "@aep-foundation/service";

export const packageName = "@aep-foundation/fastify";
export const AEP_FASTIFY_WELL_KNOWN_PATH = "/.well-known/aep";
export const AEP_FASTIFY_MEDIA_TYPE = "application/aep+json";

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
  resourceBaseUrl: string | URL
): FastifyAepHandler {
  const service = resolveService(input);
  return async (request, reply) => {
    const result = await service.authenticateProtectedResource({
      headers: request.headers ?? {},
      method: request.method ?? "GET",
      url: new URL(request.url ?? "/", resourceBaseUrl)
    });
    if (result.authenticated) return;
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

  return (_request, reply) => {
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
    const clientAssertion = parseAepAuthorization(headerValue(request.headers, "authorization"));
    const idempotencyKey = headerValue(request.headers, "idempotency-key");
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

function resolveService(input: FastifyAepServiceInput): AepService {
  return "inspectDocument" in input ? input : createAepService(input);
}
