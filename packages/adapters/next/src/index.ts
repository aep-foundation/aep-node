import { createAepService } from "@aep-foundation/service";
import type {
  AepIdempotentServiceOptions,
  AepService,
  AepServiceOptions
} from "@aep-foundation/service";

export const packageName = "@aep-foundation/next";
export const AEP_NEXT_MEDIA_TYPE = "application/aep+json";

export type NextAepServiceInput = AepService | AepServiceOptions;
export type NextAepCommand = "enroll" | "grant" | "inspect" | "revoke" | "status";
export type NextAepRouteHandler = (request?: Request) => Promise<Response> | Response;

export function createNextAepRouteHandler(input: NextAepServiceInput): NextAepRouteHandler {
  const service = resolveService(input);

  return () =>
    new Response(JSON.stringify(service.inspectDocument()), {
      headers: {
        "Content-Type": AEP_NEXT_MEDIA_TYPE
      },
      status: 200
    });
}

export function createNextAepProtectedResourceHandler(
  input: NextAepServiceInput,
  onAuthenticated: (request: Request) => Promise<Response> | Response
): NextAepRouteHandler {
  const service = resolveService(input);
  return async (request) => {
    if (request === undefined) throw new TypeError("A protected-resource request is required.");
    const result = await service.authenticateProtectedResource({
      headers: request.headers,
      method: request.method,
      url: request.url
    });
    if (result.authenticated) return onAuthenticated(request);
    return new Response(JSON.stringify(result.response.body), {
      headers: { ...result.response.headers, "Content-Type": result.response.contentType },
      status: result.response.status
    });
  };
}

export function createNextAepCommandRouteHandler(
  input: NextAepServiceInput,
  command: Exclude<NextAepCommand, "inspect">
): NextAepRouteHandler {
  const service = resolveService(input);

  return async (request) => {
    const clientAssertion = parseAepAuthorization(
      request?.headers.get("Authorization") ?? undefined
    );
    const idempotencyKey = request?.headers.get("Idempotency-Key") ?? undefined;
    const body = command === "status" ? undefined : await request?.json();
    const commandOptions = idempotentOptions(clientAssertion, idempotencyKey);
    const result =
      command === "enroll"
        ? await service.enroll(body, commandOptions)
        : command === "status"
          ? await service.status({ clientAssertion })
          : command === "grant"
            ? await service.grant(body, commandOptions)
            : await service.revoke(body, commandOptions);

    return new Response(JSON.stringify(result.body), {
      headers: {
        ...result.headers,
        "Content-Type": result.contentType
      },
      status: result.status
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

export function createNextAepRoute(
  input: NextAepServiceInput,
  command: NextAepCommand = "inspect"
): {
  GET?: NextAepRouteHandler;
  POST?: NextAepRouteHandler;
} {
  if (command === "inspect") {
    return {
      GET: createNextAepRouteHandler(input)
    };
  }

  if (command === "status") {
    return {
      GET: createNextAepCommandRouteHandler(input, command)
    };
  }

  return {
    POST: createNextAepCommandRouteHandler(input, command)
  };
}

function parseAepAuthorization(authorization: string | undefined): string {
  const prefix = "AEP ";

  if (authorization?.startsWith(prefix)) {
    return authorization.slice(prefix.length);
  }

  return "";
}

function resolveService(input: NextAepServiceInput): AepService {
  return "inspectDocument" in input ? input : createAepService(input);
}
