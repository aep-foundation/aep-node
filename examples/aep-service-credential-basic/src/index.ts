import { randomUUID } from "node:crypto";

import {
  AEP_GRANT_TYPE_BASIC,
  AEP_PROBLEM_MEDIA_TYPE,
  createProblemDetails
} from "@aep-foundation/core";
import type { BasicGrantResponse } from "@aep-foundation/core";
import { registerExpressAepRoutes } from "@aep-foundation/express";
import {
  createAepService,
  createDidWebClientAssertionVerifier,
  createInMemoryServiceCredentialStore,
  didWebIdentityMethod,
  storedBasicGrantType
} from "@aep-foundation/service";
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

const adapterName = "basic";
const host = process.env["HOST"] ?? "127.0.0.1";
const port = parsePort(process.env["PORT"] ?? "3000");
const listenUrl = exampleListenUrl(host, port);
const serviceDid = requiredExampleConfig("SERVICE_DID", process.env["SERVICE_DID"]);
const credentialStore = createInMemoryServiceCredentialStore();
const issuedBasicCredentials = new Map<string, { agentDid: string; credentialId: string }>();

const service = createAepService({
  ...exampleServicePorts(),
  clientAssertionVerifier: createDidWebClientAssertionVerifier(),
  grantTypes: [
    storedBasicGrantType({
      issue: (_request, context): BasicGrantResponse => {
        const credential: BasicGrantResponse = {
          credential_id: randomUUID(),
          expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          password: randomUUID(),
          realm: "AEP Example",
          scopes: ["read:resource", "write:profile"],
          username: randomUUID()
        };

        issuedBasicCredentials.set(basicCredentialKey(credential.username, credential.password), {
          agentDid: context.agentDid,
          credentialId: credential.credential_id
        });
        logExampleCredentialIssued(
          adapterName,
          AEP_GRANT_TYPE_BASIC,
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
  const presented = parseBasicAuthorization(request.header("authorization"));
  const issued =
    presented === undefined
      ? undefined
      : issuedBasicCredentials.get(basicCredentialKey(presented.username, presented.password));

  if (presented !== undefined && issued !== undefined) {
    const record = await findActiveCredential(
      credentialStore,
      issued.agentDid,
      AEP_GRANT_TYPE_BASIC,
      (credential) =>
        credential.credential_id === issued.credentialId &&
        "username" in credential &&
        credential.username === presented.username &&
        credential.password === presented.password
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

function parseBasicAuthorization(
  authorization: string | undefined
): { password: string; username: string } | undefined {
  const prefix = "Basic ";

  if (!authorization?.startsWith(prefix)) {
    return undefined;
  }

  const decoded = Buffer.from(authorization.slice(prefix.length), "base64").toString("utf8");
  const separator = decoded.indexOf(":");

  if (separator <= 0) {
    return undefined;
  }

  return {
    password: decoded.slice(separator + 1),
    username: decoded.slice(0, separator)
  };
}

function basicCredentialKey(username: string, password: string): string {
  return `${username}\u0000${password}`;
}
