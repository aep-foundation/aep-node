import { describe, expect, it, vi } from "vitest";
import { AEP_SERVICE_DOCUMENTS_EXTENSION, type AepServiceDocument } from "@aep-foundation/core";
import {
  buildInspectDocument,
  createAepService,
  createInMemoryEnrollmentStore,
  createInMemoryCommandIdempotencyStore,
  createStaticEnrollmentPolicy,
  didWebIdentityMethod,
  handleEnrollRequest,
  handleGrantRequest,
  type AepEnrollmentRecord,
  type AepGrantTypeHandler
} from "../src/index.js";

const agentDid = "did:web:agent.example.com";
const document = (
  id: string,
  enrollment: "required" | "not-required" = "required"
): AepServiceDocument => ({
  id,
  type: "terms_of_service",
  title: id,
  enrollment,
  representations: [{ media_type: "text/html", url: `https://example.com/${id}` }]
});
const existing: AepEnrollmentRecord = {
  agentDid,
  claims: { "contact.email": "owner@example.com" },
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  since: "2026-01-01T00:00:00Z",
  status: "active",
  ownerActionRequired: false,
  requirementsPending: []
};

function setup(records: AepEnrollmentRecord[] = []) {
  const store = createInMemoryEnrollmentStore(records);
  const commandIdempotencyStore = createInMemoryCommandIdempotencyStore();
  const serviceDocuments = [document("terms"), document("privacy", "not-required")];
  const policy = createStaticEnrollmentPolicy();
  const grant = vi.fn(() => ({ token: "credential" }));
  const handler: AepGrantTypeHandler = { grant, revoke: () => undefined };
  const options = {
    store,
    commandIdempotencyStore,
    serviceDocuments,
    policy,
    clock: () => new Date("2026-10-28T00:00:00Z")
  };
  return {
    ...options,
    grant,
    enroll: (request: object, key: string) =>
      handleEnrollRequest({ agent_did: agentDid, ...request }, { ...options, idempotencyKey: key }),
    getGrant: (key: string, requiredClaims: string[] = []) =>
      handleGrantRequest(
        { grant_type: "api-key" },
        {
          agentDid,
          commandIdempotencyStore,
          handlers: new Map([["api-key", handler]]),
          store,
          serviceDocuments,
          requiredClaims,
          idempotencyKey: key
        }
      )
  };
}

describe("Service document enrollment lifecycle", () => {
  it.each([
    { missingClaim: true, missingDocument: false },
    { missingClaim: false, missingDocument: true },
    { missingClaim: true, missingDocument: true }
  ])(
    "rejects repeated enrollment with unmet requirements: %j",
    async ({ missingClaim, missingDocument }) => {
      const record = {
        ...existing,
        acknowledgedDocumentIds: missingDocument ? [] : ["terms"]
      };
      const state = setup([record]);
      const before = await state.store.findEnrollment(agentDid);
      const decide = vi.spyOn(state.policy, "decideEnrollment");
      const save = vi.spyOn(state.store, "saveEnrollment");
      const response = await handleEnrollRequest(
        { agent_did: agentDid },
        {
          ...state,
          requiredClaims: missingClaim ? ["person.name"] : [],
          idempotencyKey: "missing-requirements"
        }
      );
      expect(response.status).toBe(422);
      expect(response.body).toMatchObject({
        code: "requirements_unmet",
        requirements_pending: [
          ...(missingClaim ? ["person.name"] : []),
          ...(missingDocument ? ["service_documents"] : [])
        ]
      });
      if (missingDocument)
        expect(response.body).toMatchObject({
          required_document_ids: ["terms"],
          owner_action_required: "true"
        });
      else expect(response.body).not.toHaveProperty("required_document_ids");
      expect(decide).toHaveBeenCalledOnce();
      expect(save).not.toHaveBeenCalled();
      expect(await state.store.findEnrollment(agentDid)).toEqual(before);
    }
  );

  it.each([
    [false, undefined],
    [false, false],
    [false, true],
    [true, undefined],
    [true, false],
    [true, true]
  ] as const)(
    "resolves optional policy metadata (existing=%s, value=%s)",
    async (repeated, value) => {
      const state = setup(
        repeated
          ? [
              {
                ...existing,
                status: "suspended",
                ownerActionRequired: true,
                requirementsPending: ["review"],
                verificationPending: ["contact.email"]
              }
            ]
          : []
      );
      const policy = createStaticEnrollmentPolicy(
        value === undefined
          ? {}
          : {
              ownerActionRequired: value,
              requirementsPending: [],
              verificationPending: []
            }
      );
      const response = await handleEnrollRequest(
        {
          agent_did: agentDid,
          acknowledged_document_ids: ["terms"]
        },
        { ...state, policy, idempotencyKey: "metadata" }
      );
      expect(response.status).toBe(200);
      expect(await state.store.findEnrollment(agentDid)).toMatchObject({
        status: repeated ? "suspended" : "active",
        ownerActionRequired: value ?? repeated,
        requirementsPending: repeated && value === undefined ? ["review"] : [],
        verificationPending: repeated && value === undefined ? ["contact.email"] : []
      });
    }
  );

  it("advertises only configured documents and keeps input isolated", () => {
    const documents = [document("terms")];
    const options = {
      serviceDid: "did:web:example.com",
      identityMethods: [didWebIdentityMethod()],
      serviceDocuments: documents
    };
    const service = createAepService(options);
    documents[0]?.representations.splice(0);
    expect(service.inspectDocument().service_documents?.[0]?.representations).toHaveLength(1);
    expect(service.inspectDocument().extensions?.supported).toContain(
      AEP_SERVICE_DOCUMENTS_EXTENSION
    );
    expect(
      buildInspectDocument({ ...options, serviceDocuments: [] }).service_documents
    ).toBeUndefined();
    expect(() =>
      buildInspectDocument({ ...options, serviceDocuments: [document("terms"), document("terms")] })
    ).toThrow();
  });

  it("requires an explicit declaration, echoes only that declaration and never accepts not-required documents implicitly", async () => {
    const state = setup();
    expect((await state.enroll({}, "missing")).body).toMatchObject({
      code: "requirements_unmet",
      required_document_ids: ["terms"],
      requirements_pending: ["service_documents"]
    });
    expect(await state.store.findEnrollment(agentDid)).toBeUndefined();
    expect((await state.enroll({ acknowledged_document_ids: ["terms"] }, "accept")).body).toEqual({
      status: "active",
      acknowledged_document_ids: ["terms"]
    });
    expect((await state.store.findEnrollment(agentDid))?.acknowledgedDocumentIds).toEqual([
      "terms"
    ]);
    expect((await state.enroll({}, "repeat")).body).toEqual({ status: "active" });
    expect((await state.getGrant("grant")).status).toBe(200);
    expect(state.grant).toHaveBeenCalledOnce();
  });

  it("accepts an older approved list, then exposes newly required documents on a later Grant", async () => {
    const state = setup();
    state.serviceDocuments.push(document("extra"));
    expect(
      (await state.enroll({ acknowledged_document_ids: ["terms"] }, "approved-earlier")).status
    ).toBe(200);
    expect((await state.getGrant("blocked")).body).toMatchObject({
      code: "requirements_unmet",
      required_document_ids: ["extra"]
    });
    expect(state.grant).not.toHaveBeenCalled();
    const retry = await state.enroll({ acknowledged_document_ids: ["extra"] }, "update");
    expect(retry.body).toEqual({ status: "active", acknowledged_document_ids: ["extra"] });
    expect((await state.store.findEnrollment(agentDid))?.acknowledgedDocumentIds).toEqual([
      "terms",
      "extra"
    ]);
    expect((await state.getGrant("blocked")).status).toBe(422);
    expect((await state.getGrant("new-grant")).status).toBe(200);
  });

  it("preserves explicit empty declarations and opaque retired IDs without satisfying another requirement", async () => {
    const state = setup();
    expect((await state.enroll({ acknowledged_document_ids: [] }, "empty")).body).toEqual({
      status: "active",
      acknowledged_document_ids: []
    });
    expect((await state.enroll({ acknowledged_document_ids: ["retired"] }, "retired")).status).toBe(
      200
    );
    expect((await state.getGrant("missing")).body).toMatchObject({
      required_document_ids: ["terms"]
    });
    expect((await state.store.findEnrollment(agentDid))?.acknowledgedDocumentIds).toEqual([]);
    expect(state.grant).not.toHaveBeenCalled();
  });

  it("allows Services to require renewed acceptance of an already acknowledged ID", async () => {
    const state = setup([
      { ...existing, acknowledgedDocumentIds: ["terms"], requiredDocumentIds: ["terms"] }
    ]);
    expect((await state.getGrant("renewal-required")).status).toBe(422);
    await state.enroll({ acknowledged_document_ids: ["terms"] }, "renew");
    expect((await state.store.findEnrollment(agentDid))?.requiredDocumentIds).toEqual([]);
    expect((await state.getGrant("renewed")).status).toBe(200);
  });

  it.each(["active", "suspended", "terminated", "pending", "unavailable"] as const)(
    "preserves %s lifecycle and unspecified claims during updates",
    async (status) => {
      const record = {
        ...existing,
        status,
        ownerActionRequired: true,
        requirementsPending: ["review"],
        verificationPending: ["contact.email"]
      };
      const state = setup([record]);
      await state.enroll(
        { acknowledged_document_ids: ["terms"], claims: { "person.name": "Owner" } },
        "update"
      );
      const stored = await state.store.findEnrollment(agentDid);
      expect(stored).toMatchObject({
        ...record,
        claims: { ...record.claims, "person.name": "Owner" },
        updatedAt: "2026-10-28T00:00:00.000Z",
        acknowledgedDocumentIds: ["terms"]
      });
      expect(stored?.since).toBe(record.since);
    }
  );

  it("lets policy read its store and honors rejection or unchanged decisions", async () => {
    const state = setup([existing]);
    for (const decision of [{ status: "rejected" as const }, { updateExisting: false }]) {
      const response = await handleEnrollRequest(
        { agent_did: agentDid, acknowledged_document_ids: ["terms"] },
        {
          ...state,
          idempotencyKey: JSON.stringify(decision),
          policy: {
            async decideEnrollment(request, context) {
              expect(context).toEqual({ now: new Date("2026-10-28T00:00:00Z") });
              expect(await state.store.findEnrollment(request.agent_did)).toMatchObject(existing);
              return decision;
            }
          }
        }
      );
      expect(response.status).toBe(decision.status === "rejected" ? 403 : 200);
      expect(await state.store.findEnrollment(agentDid)).toEqual({
        ...existing,
        verificationPending: []
      });
    }
  });

  it("applies explicit static policy values without resetting omitted metadata", async () => {
    const state = setup([
      {
        ...existing,
        ownerActionRequired: true,
        requirementsPending: ["review"],
        verificationPending: ["contact.email"]
      }
    ]);
    const requirementsPending: string[] = [];
    const policy = createStaticEnrollmentPolicy({
      ownerActionRequired: false,
      requirementsPending
    });
    const decision = await policy.decideEnrollment({ agent_did: agentDid }, { now: new Date() });
    decision.requirementsPending?.push("mutation");
    expect(requirementsPending).toEqual([]);
    await handleEnrollRequest(
      { agent_did: agentDid, acknowledged_document_ids: ["terms"] },
      { ...state, policy, idempotencyKey: "explicit-metadata" }
    );
    expect(await state.store.findEnrollment(agentDid)).toMatchObject({
      ownerActionRequired: false,
      requirementsPending: [],
      verificationPending: ["contact.email"]
    });
  });

  it("replays the same operation without new effects and rejects conflicting declarations", async () => {
    const state = setup();
    const request = { acknowledged_document_ids: ["terms"] };
    const responses = await Promise.all([
      state.enroll(request, "same"),
      state.enroll(request, "same")
    ]);
    expect(responses[0]).toEqual(responses[1]);
    const before = await state.store.findEnrollment(agentDid);
    expect((await state.enroll({ acknowledged_document_ids: [] }, "same")).status).toBe(409);
    expect(await state.store.findEnrollment(agentDid)).toEqual(before);
  });

  it("requires newly missing claims at Grant without losing existing claims during Enroll", async () => {
    const state = setup([{ ...existing, acknowledgedDocumentIds: ["terms"] }]);
    expect((await state.getGrant("claims", ["contact.email", "person.name"])).body).toMatchObject({
      requirements_pending: ["person.name"]
    });
    await handleEnrollRequest(
      { agent_did: agentDid, claims: { "person.name": "Owner" } },
      { ...state, requiredClaims: ["contact.email", "person.name"], idempotencyKey: "new-claim" }
    );
    expect(
      (await state.getGrant("claims-satisfied", ["contact.email", "person.name"])).status
    ).toBe(200);
  });

  it("keeps no-extension behavior and does not disclose requirements to unknown identities", async () => {
    const state = setup();
    const unknown = await state.getGrant("unknown");
    expect(unknown.body).toMatchObject({ code: "not_recognized" });
    expect(unknown.body).not.toHaveProperty("required_document_ids");
    const response = await handleEnrollRequest(
      { agent_did: agentDid, acknowledged_document_ids: ["terms"] },
      {
        store: state.store,
        policy: state.policy,
        idempotencyKey: "unsupported"
      }
    );
    expect(response.body).toEqual({ status: "active" });
    expect((await state.store.findEnrollment(agentDid))?.acknowledgedDocumentIds).toBeUndefined();
  });
});
