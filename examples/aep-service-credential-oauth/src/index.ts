import { randomUUID } from "node:crypto";

import {
  AEP_GRANT_TYPE_OAUTH_BEARER,
  AEP_PROBLEM_MEDIA_TYPE,
  createProblemDetails
} from "@aep-foundation/core";
import { registerExpressAepRoutes } from "@aep-foundation/express";
import {
  createAepService,
  createDidWebClientAssertionVerifier,
  createInMemoryServiceCredentialStore,
  didWebIdentityMethod,
  storedOAuthBearerGrantType
} from "@aep-foundation/service";
import type { OAuthBearerGrantResponse } from "@aep-foundation/core";
import express from "express";
import type { Request, RequestHandler, Response } from "express";

import {
  exampleListenUrl,
  exampleServicePorts,
  findActiveCredential,
  logExampleCredentialIssued,
  logExampleServiceInteraction,
  parsePort,
  profileBody,
  requiredExampleConfig,
  resourceBody
} from "../../_shared/aep-examples.js";

const adapterName = "oauth-bearer";
const host = process.env["HOST"] ?? "127.0.0.1";
const port = parsePort(process.env["PORT"] ?? "3000");
const listenUrl = exampleListenUrl(host, port);
const serviceDid = requiredExampleConfig("SERVICE_DID", process.env["SERVICE_DID"]);
const credentialStore = createInMemoryServiceCredentialStore();
const issuedBearerTokens = new Map<string, { agentDid: string; credentialId: string }>();

const service = createAepService({
  ...exampleServicePorts(),
  clientAssertionVerifier: createDidWebClientAssertionVerifier(),
  grantTypes: [
    storedOAuthBearerGrantType({
      issue: (_request, context): OAuthBearerGrantResponse => {
        const credential: OAuthBearerGrantResponse = {
          access_token: randomUUID(),
          credential_id: randomUUID(),
          expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          scopes: ["read:resource", "write:profile"],
          token_type: "Bearer"
        };

        issuedBearerTokens.set(credential.access_token, {
          agentDid: context.agentDid,
          credentialId: credential.credential_id
        });
        logExampleCredentialIssued(
          adapterName,
          AEP_GRANT_TYPE_OAUTH_BEARER,
          context.agentDid,
          credential.credential_id
        );
        return credential;
      },
      store: credentialStore
    })
  ],
  identityMethods: [didWebIdentityMethod()],
  serviceDid
});

const requireCredential: RequestHandler = (request, response, next) => {
  void authenticateCredential(request, response)
    .then((authenticated) => {
      if (authenticated) {
        next();
      }
    })
    .catch(next);
};

const app = express();
app.use(express.json({ type: ["application/json", "application/aep+json"] }));
app.use((request, response, next) => {
  response.on("finish", () => {
    logExampleServiceInteraction(adapterName, request.method, request.path, response.statusCode);
  });
  next();
});
registerExpressAepRoutes(app, service);
app.get("/api/resource", requireCredential, (_request, response) => {
  response.json(resourceBody(adapterName));
});
app.post("/api/profile", requireCredential, (request, response) => {
  response.json(profileBody(adapterName, request.body as unknown));
});

app.listen(port, host, () => {
  console.log(`AEP ${adapterName} credential service listening on ${listenUrl}`);
  console.log(`Service DID: ${serviceDid}`);
});

async function authenticateCredential(request: Request, response: Response): Promise<boolean> {
  const authorization = request.header("authorization");
  const prefix = "Bearer ";
  const token = authorization?.startsWith(prefix) ? authorization.slice(prefix.length) : undefined;
  const issued = token === undefined ? undefined : issuedBearerTokens.get(token);

  if (token !== undefined && issued !== undefined) {
    const record = await findActiveCredential(
      credentialStore,
      issued.agentDid,
      AEP_GRANT_TYPE_OAUTH_BEARER,
      (credential) =>
        credential.credential_id === issued.credentialId &&
        "access_token" in credential &&
        credential.token_type === "Bearer" &&
        credential.access_token === token
    );

    if (record !== undefined) {
      return true;
    }
  }

  response
    .type(AEP_PROBLEM_MEDIA_TYPE)
    .status(401)
    .json(createProblemDetails({ code: "not_recognized", status: 401, title: "Not recognized" }));
  return false;
}
