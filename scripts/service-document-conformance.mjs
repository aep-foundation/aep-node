import { isDeepStrictEqual } from "node:util";
import {
  AEP_SERVICE_DOCUMENTS_EXTENSION,
  validateInspectDocument,
  validateAepServiceDocuments,
  validateAepPortableDocument,
  validateEnrollRequest,
  validateEnrollResponse,
  validateProblemDetails
} from "../packages/core/dist/index.js";
import {
  createInMemoryEnrollmentStore,
  createInMemoryCommandIdempotencyStore,
  createStaticEnrollmentPolicy,
  handleEnrollRequest,
  handleGrantRequest
} from "../packages/service/dist/index.js";

export async function evaluateServiceDocuments(id, testCase) {
  const { input, expected } = testCase;
  if (id === "wire-shapes")
    return input.cases.every((item, index) => {
      let valid;
      switch (item.schema) {
        case "service-documents.schema.json":
          valid =
            item.value.service_documents === undefined ||
            (item.value.extensions?.supported?.includes(AEP_SERVICE_DOCUMENTS_EXTENSION) &&
              validateAepServiceDocuments(item.value.service_documents).ok);
          break;
        case "portable-service-document.schema.json":
          valid = validateAepPortableDocument(item.value).ok;
          break;
        case "enroll-request.schema.json":
          valid = validateEnrollRequest(item.value).ok;
          break;
        case "enroll-response.schema.json":
          valid = validateEnrollResponse(item.value).ok;
          break;
      case "problem.schema.json":
          valid = validateProblemDetails(item.value).ok;
          break;
        case "inspect-document.schema.json":
          valid = validateInspectDocument(item.value).ok;
          break;
        default:
          throw new Error(`Unsupported document schema: ${item.schema}`);
      }
      if (Boolean(valid) !== expected.cases[index].valid)
        throw new Error(`Wire case failed: ${item.name}`);
      return true;
    });
  if (id === "structural-limits")
    return input.cases.every((item, index) => {
      const descriptor = structuredClone(input.descriptor);
      const document = structuredClone(input.document);
      let catalog;
      switch (item.kind) {
        case "catalog":
          catalog = Array.from({ length: item.count }, (_, i) => ({
            ...descriptor,
            id: `doc-${i}`
          }));
          break;
        case "duplicate-ids":
          catalog = [descriptor, descriptor];
          break;
        case "duplicate-media":
          descriptor.representations.push(descriptor.representations[0]);
          catalog = [descriptor];
          break;
        case "blocks":
          document.content = Array(item.content_count).fill(document.content[0]);
          document.summary = Array(item.summary_count).fill(document.content[0]);
          break;
        case "sections":
          for (let i = 0; i < item.depth; i++)
            document.content = [{ type: "section", title: "Title", blocks: document.content }];
          break;
        case "text":
          document.content[0].text = "a".repeat(item.length);
          break;
        case "list":
          document.content = [{ type: "bulleted_list", items: Array(item.count).fill("Item") }];
          break;
        case "title":
          descriptor.title = "a".repeat(item.length);
          catalog = [descriptor];
          break;
        case "url": {
          const prefix = "https://example.com/";
          descriptor.representations[0].url = prefix + "a".repeat(item.length - prefix.length);
          catalog = [descriptor];
          break;
        }
        default:
          throw new Error(`Unsupported structural case: ${item.kind}`);
      }
      const valid =
        catalog === undefined
          ? validateAepPortableDocument(document).ok
          : validateAepServiceDocuments(catalog).ok;
      if (valid !== expected.cases[index].valid)
        throw new Error(`Structural case failed: ${item.name}`);
      return true;
    });
  if (id === "enrollment-lifecycle") return lifecycle(input, expected);
  if (id === "grant-guidance") return grantGuidance(input, expected);
  throw new Error(`Unsupported Service Documents vector: ${id}`);
}

function descriptor(id) {
  return {
    id,
    type: "terms_of_service",
    title: id,
    enrollment: "required",
    representations: [{ media_type: "text/html", url: `https://example.com/${id}` }]
  };
}

function record(existing) {
  return {
    agentDid: existing.agent_did,
    claims: existing.claims ?? {},
    createdAt: existing.created,
    updatedAt: existing.created,
    since: existing.since,
    status: existing.status,
    ownerActionRequired: false,
    requirementsPending: [],
    acknowledgedDocumentIds: existing.acknowledged_document_ids ?? [],
    enrollmentId: existing.enrollment_id,
    credentialIds: existing.credential_ids
  };
}

async function lifecycle(input, expected) {
  const initial = record(input.existing);
  const store = createInMemoryEnrollmentStore([initial]);
  let effects = 0;
  const options = {
    store,
    commandIdempotencyStore: createInMemoryCommandIdempotencyStore(),
    serviceDocuments: input.current_required_ids.map(descriptor),
    policy: {
      decideEnrollment: () => {
        effects++;
        return {};
      }
    }
  };
  for (const [index, operation] of input.operations.entries()) {
    if (operation.mark_required)
      await store.saveEnrollment({
        ...(await store.findEnrollment(initial.agentDid)),
        requiredDocumentIds: operation.mark_required
      });
    const before = await store.findEnrollment(initial.agentDid);
    const priorEffects = effects;
    const response = await handleEnrollRequest(
      {
        agent_did: initial.agentDid,
        ...(operation.claims ? { claims: operation.claims } : {}),
        acknowledged_document_ids: operation.acknowledged_document_ids
      },
      { ...options, idempotencyKey: operation.key }
    );
    const result = expected.operations[index];
    const after = await store.findEnrollment(initial.agentDid);
    if (response.status !== result.http_status) return false;
    if (result.code && response.body.code !== result.code) return false;
    if (
      result.acknowledged_document_ids &&
      !isDeepStrictEqual(response.body.acknowledged_document_ids, result.acknowledged_document_ids)
    )
      return false;
    if (result.stored_ids && !isDeepStrictEqual(after.acknowledgedDocumentIds, result.stored_ids))
      return false;
    if (result.mutated === false && !isDeepStrictEqual(after, before)) return false;
    if (result.policy_effects_repeated === false && effects !== priorEffects) return false;
    if (result.requirement_satisfied && after.requiredDocumentIds.includes("terms")) return false;
    if (index === 0) {
      const grant = await handleGrantRequest(
        { grant_type: "api-key" },
        {
          ...options,
          agentDid: initial.agentDid,
          idempotencyKey: "missing-new",
          handlers: new Map([
            [
              "api-key",
              {
                grant: () => {
                  throw new Error("Must not grant");
                }
              }
            ]
          ])
        }
      );
      if (
        !isDeepStrictEqual(grant.body.required_document_ids, expected.outstanding_ids_after_update)
      )
        return false;
    }
  }
  const after = await store.findEnrollment(initial.agentDid);
  if (
    !isDeepStrictEqual(after.claims, expected.claims) ||
    after.createdAt !== initial.createdAt ||
    after.since !== initial.since ||
    after.enrollmentId !== initial.enrollmentId ||
    !isDeepStrictEqual(after.credentialIds, expected.credential_ids)
  )
    return false;
  for (const status of input.lifecycle_states) {
    await store.saveEnrollment({ ...after, status });
    await handleEnrollRequest(
      { agent_did: initial.agentDid, acknowledged_document_ids: [] },
      { ...options, idempotencyKey: status }
    );
    if ((await store.findEnrollment(initial.agentDid)).status !== status) return false;
  }
  return true;
}

async function grantGuidance(input, expected) {
  const agentDid = input.enroll_requests[0].agent_did;
  const initial = record({
    agent_did: agentDid,
    created: "2026-10-01T00:00:00Z",
    since: "2026-10-01T00:00:00Z",
    status: "active"
  });
  const store = createInMemoryEnrollmentStore([initial]);
  let issued = false;
  const options = {
    store,
    agentDid,
    idempotencyKey: "grant",
    serviceDocuments: input.required_document_ids.map(descriptor),
    requiredClaims: input.missing_claims,
    handlers: new Map([
      [
        "api-key",
        {
          grant: () => {
            issued = true;
            return {};
          }
        }
      ]
    ])
  };
  const response = await handleGrantRequest({ grant_type: "api-key" }, options);
  if (
    response.status !== expected.grant_status ||
    issued ||
    !isDeepStrictEqual(response.body.required_document_ids, input.required_document_ids)
  )
    return false;
  const unknown = await handleGrantRequest(
    { grant_type: "api-key" },
    { ...options, agentDid: "did:example:unknown" }
  );
  if (
    unknown.status !== expected.unrecognized.http_status ||
    unknown.body.code !== expected.unrecognized.code ||
    unknown.body.required_document_ids !== undefined
  )
    return false;
  for (const [index, request] of input.enroll_requests.entries()) {
    const result = await handleEnrollRequest(request, {
      ...options,
      store: createInMemoryEnrollmentStore(),
      policy: createStaticEnrollmentPolicy(),
      idempotencyKey: request.name
    });
    if (result.status !== expected.enroll_requests[index].http_status) return false;
    if (
      request.acknowledged_document_ids &&
      !isDeepStrictEqual(result.body.acknowledged_document_ids, request.acknowledged_document_ids)
    )
      return false;
  }
  return true;
}
