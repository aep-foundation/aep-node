import { describe, expect, it, vi } from "vitest";
import {
  AEP_SERVICE_DOCUMENTS_EXTENSION,
  parseEnrollRequest,
  type InspectDocument
} from "@aep-foundation/core";
import {
  AepCommandError,
  enrollService,
  grantService,
  createAepAgent,
  type InspectServiceResult
} from "../src/index.js";

const document: InspectDocument = {
  aep_version: "1.0",
  http: { endpoint_base: "/aep/" },
  service: { did: "did:web:example.com" },
  commands: {
    supported: ["inspect", "enroll", "grant", "status", "revoke"],
    grant_types: ["api-key"]
  },
  core: { signing_algorithms: ["ES256", "EdDSA"] },
  bindings: { supported: ["http"] },
  identity: { methods: ["did:web"] },
  extensions: { supported: [AEP_SERVICE_DOCUMENTS_EXTENSION] },
  claims: { required: ["contact.email"], optional: [], preferred: [] },
  service_documents: [
    {
      id: "terms",
      type: "terms_of_service",
      title: "Terms",
      enrollment: "required",
      representations: [{ media_type: "text/html", url: "https://example.com/terms" }]
    }
  ]
};
const inspect: InspectServiceResult = {
  document,
  inspectUrl: new URL("https://example.com/.well-known/aep"),
  commandUrl: (command) => new URL(`/aep/${command}`, "https://example.com")
};
const options = {
  agentDid: "did:web:agent.example.com",
  clientAssertion: "test-assertion",
  inspect,
  serviceUrl: "https://example.com",
  idempotencyKey: "explicit-operation"
};

describe("Agent Service Documents", () => {
  it.for([undefined, [], ["terms"], ["retired", "terms"]])(
    "sends only caller-authorized acknowledgements: %j",
    async (ids) => {
      const fetch = vi.fn((_url: string | URL, init?: RequestInit) => {
        if (typeof init?.body !== "string") throw new TypeError("Expected JSON body.");
        const body: unknown = JSON.parse(init.body);
        if (ids === undefined) expect(body).not.toHaveProperty("acknowledged_document_ids");
        else expect(body).toMatchObject({ acknowledged_document_ids: ids });
        return Promise.resolve(
          Response.json({
            status: "active",
            ...(ids === undefined ? {} : { acknowledged_document_ids: ids })
          })
        );
      });
      const result = await enrollService({
        ...options,
        fetch,
        ...(ids === undefined ? {} : { acknowledgedDocumentIds: ids })
      });
      expect(result.body.acknowledged_document_ids).toEqual(ids);
      expect(fetch).toHaveBeenCalledOnce();
    }
  );

  it("does not send malformed lists or acknowledgements to unsupported Services", async () => {
    const fetch = vi.fn();
    await expect(
      enrollService({ ...options, fetch, acknowledgedDocumentIds: ["terms", "terms"] })
    ).rejects.toThrow();
    await expect(
      enrollService({
        ...options,
        fetch,
        inspect: { ...inspect, document: { ...document, extensions: { supported: [] } } },
        acknowledgedDocumentIds: ["terms"]
      })
    ).rejects.toThrow("does not advertise");
    expect(fetch).not.toHaveBeenCalled();
  });

  it.for([undefined, [], ["extra"], ["terms", "extra"]])(
    "rejects a changed acknowledgement echo: %j",
    async (echo) => {
      await expect(
        enrollService({
          ...options,
          acknowledgedDocumentIds: ["terms"],
          fetch: () =>
            Promise.resolve(
              Response.json({
                status: "active",
                ...(echo === undefined ? {} : { acknowledged_document_ids: echo })
              })
            )
        })
      ).rejects.toThrow("different document acknowledgement");
    }
  );

  it("does not treat a rejected enrollment as document acceptance", async () => {
    const result = await enrollService({
      ...options,
      acknowledgedDocumentIds: ["terms"],
      fetch: () => Promise.resolve(Response.json({ status: "rejected" }))
    });
    expect(result.body.status).toBe("rejected");
    expect(result.body.acknowledged_document_ids).toBeUndefined();
  });

  it("preserves requirement errors without enrolling or retrying Grant", async () => {
    const problem = {
      type: "urn:aep:error:requirements_unmet",
      code: "requirements_unmet",
      title: "Requirements unmet",
      status: 422,
      requirements_pending: ["contact.email", "service_documents"],
      required_document_ids: ["terms"]
    };
    const fetch = vi.fn(() => Promise.resolve(Response.json(problem, { status: 422 })));
    const promise = grantService({ ...options, fetch, grantType: "api-key" });
    await expect(promise).rejects.toBeInstanceOf(AepCommandError);
    await expect(promise).rejects.toMatchObject({ problem });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("allows explicit repeated session enrollment with new declarations", async () => {
    const requests: unknown[] = [];
    const fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      if ((url instanceof Request ? url.url : String(url)).endsWith("/.well-known/aep"))
        return Promise.resolve(
          Response.json(document, { headers: { "content-type": "application/aep+json" } })
        );
      if (typeof init?.body !== "string") throw new TypeError("Expected JSON body.");
      const body = parseEnrollRequest(JSON.parse(init.body));
      requests.push(body);
      return Promise.resolve(
        Response.json({
          status: "active",
          acknowledged_document_ids: body.acknowledged_document_ids
        })
      );
    });
    const agent = createAepAgent({
      fetch,
      identityProvider: {
        getOrCreateIdentity: () => ({
          agentDid: options.agentDid,
          serviceDid: document.service.did,
          identityKind: "sovereign",
          signingAlgorithms: ["ES256"]
        }),
        signerFor: () => () => "test-assertion"
      }
    });
    const session = agent.serviceSession({ serviceUrl: "https://example.com" });
    await session.enroll({ idempotencyKey: "first", acknowledgedDocumentIds: ["terms"] });
    await session.enroll({ idempotencyKey: "second", acknowledgedDocumentIds: [] });
    expect(requests).toHaveLength(2);
    expect(requests[1]).toMatchObject({ acknowledged_document_ids: [], idempotency_key: "second" });
  });
});
