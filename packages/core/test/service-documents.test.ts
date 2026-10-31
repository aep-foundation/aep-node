import { describe, expect, it } from "vitest";
import {
  AEP_SERVICE_DOCUMENTS_EXTENSION,
  parseAepDocumentIds,
  parseAepPortableDocument,
  parseAepServiceDocuments,
  validateAepDocumentIds,
  validateAepPortableDocument,
  validateAepServiceDocuments,
  validateEnrollRequest,
  validateEnrollResponse,
  validateProblemDetails,
  validateInspectDocument,
  type AepDocumentBlock
} from "../src/index.js";

const descriptor = {
  id: "Terms.1",
  type: "custom_terms",
  title: "Terms",
  enrollment: "required",
  representations: [{ media_type: "text/html", url: "https://example.com/terms" }]
};
const portable = {
  format: "aep-service-document",
  version: "1.0",
  id: "Terms.1",
  content: [{ type: "paragraph", text: "Full text." }]
};

describe("Service Documents", () => {
  it.each(["required", "not-required"])("preserves the %s enrollment requirement", (enrollment) => {
    expect(parseAepServiceDocuments([{ ...descriptor, enrollment }])[0]?.enrollment).toBe(
      enrollment
    );
  });

  it("preserves open types, additive fields and distinct case-sensitive IDs", () => {
    expect(parseAepServiceDocuments([{ ...descriptor, extra: true }])[0]).toMatchObject({
      type: "custom_terms",
      extra: true
    });
    expect(parseAepDocumentIds(["Terms.1", "terms.1"])).toEqual(["Terms.1", "terms.1"]);
    expect(parseAepDocumentIds([])).toEqual([]);
    expect(parseAepDocumentIds(["a".repeat(32)])).toHaveLength(1);
    expect(parseAepDocumentIds(Array.from({ length: 7 }, (_, i) => String(i)))).toHaveLength(7);
  });

  it.for([
    null,
    "terms",
    ["terms", "terms"],
    [""],
    ["terms\n"],
    ["a".repeat(33)],
    ["terms,privacy"],
    ["é"],
    Array.from({ length: 8 }, (_, i) => String(i))
  ])("rejects malformed ID arrays: %j", (ids) => {
    expect(validateAepDocumentIds(ids).ok).toBe(false);
    expect(() => parseAepDocumentIds(ids)).toThrow();
    expect(
      validateEnrollRequest({ agent_did: "did:web:agent.example", acknowledged_document_ids: ids })
        .ok
    ).toBe(false);
    expect(validateEnrollResponse({ status: "active", acknowledged_document_ids: ids }).ok).toBe(
      false
    );
  });

  it.for([
    null,
    [],
    Array.from({ length: 8 }, () => descriptor),
    [null],
    [descriptor, descriptor],
    [{ ...descriptor, id: "!" }],
    [{ ...descriptor, type: "terms\n" }],
    [{ ...descriptor, type: "Terms" }],
    [{ ...descriptor, title: "" }],
    [{ ...descriptor, enrollment: "optional" }],
    [{ ...descriptor, representations: [] }],
    [{ ...descriptor, representations: [null] }],
    [
      {
        ...descriptor,
        representations: [{ media_type: "text/markdown", url: "https://example.com" }]
      }
    ],
    [
      {
        ...descriptor,
        representations: [...descriptor.representations, ...descriptor.representations]
      }
    ],
    [
      {
        ...descriptor,
        representations: [{ media_type: "text/html\n", url: "https://example.com" }]
      }
    ]
  ])("rejects incomplete or ambiguous descriptors: %j", (documents) => {
    expect(validateAepServiceDocuments(documents).ok).toBe(false);
    expect(() => parseAepServiceDocuments(documents)).toThrow();
  });

  it.each([
    "http://example.com",
    "http://localhost.example.com",
    "http://192.168.1.10",
    "http://user@localhost",
    "https://user:pass@example.com",
    "https://example.com/space here",
    "https://example.com/é",
    "https://example.com/" + "x".repeat(2048),
    "https://[invalid]",
    "https://example.com\\path"
  ])("rejects invalid representation URLs: %s", (url) => {
    expect(
      validateAepServiceDocuments([
        { ...descriptor, representations: [{ media_type: "text/html", url }] }
      ]).ok
    ).toBe(false);
  });

  it.each([
    "http://localhost:8080/terms",
    "http://127.0.0.1/terms",
    "http://[::1]/terms",
    "https://192.168.1.10/terms"
  ])("accepts HTTPS and loopback development URLs: %s", (url) => {
    expect(
      validateAepServiceDocuments([
        { ...descriptor, representations: [{ media_type: "text/html", url }] }
      ]).ok
    ).toBe(true);
  });

  it("counts Unicode characters rather than UTF-16 code units", () => {
    expect(validateAepServiceDocuments([{ ...descriptor, title: "😀".repeat(256) }]).ok).toBe(true);
    expect(validateAepServiceDocuments([{ ...descriptor, title: "😀".repeat(257) }]).ok).toBe(
      false
    );
  });

  it("parses all block kinds and optional service-authored summaries", () => {
    const document = {
      ...portable,
      summary: [{ type: "paragraph", text: "Summary" }],
      content: [
        {
          type: "section",
          title: "Section",
          blocks: [
            { type: "bulleted_list", items: ["One", "Two"] },
            { type: "numbered_list", items: ["First"] }
          ]
        }
      ],
      future: true
    };
    expect(parseAepPortableDocument(document)).toEqual(document);
    expect(parseAepPortableDocument(portable)).toEqual(portable);
  });

  it.each([
    null,
    { ...portable, format: "other" },
    { ...portable, version: "2.0" },
    { ...portable, id: "" },
    { ...portable, summary: [] },
    { ...portable, content: [] },
    ...[
      null,
      { type: "unknown" },
      { type: "paragraph", text: "" },
      { type: "paragraph", text: "x".repeat(16385) },
      { type: "section", title: "", blocks: [] },
      { type: "bulleted_list", items: [] },
      { type: "numbered_list", items: Array(129).fill("a") },
      { type: "bulleted_list", items: [false] }
    ].map((block) => ({ ...portable, content: [block] }))
  ])("rejects unsupported or invalid content without dropping blocks", (document) => {
    expect(validateAepPortableDocument(document).ok).toBe(false);
    expect(() => parseAepPortableDocument(document)).toThrow();
  });

  it("enforces aggregate block and nested-section limits", () => {
    expect(
      validateAepPortableDocument({
        ...portable,
        content: Array(1024).fill({ type: "paragraph", text: "a" })
      }).ok
    ).toBe(true);
    expect(
      validateAepPortableDocument({
        ...portable,
        content: Array(1024).fill({ type: "paragraph", text: "a" }),
        summary: portable.content
      }).ok
    ).toBe(false);
    let block: AepDocumentBlock = { type: "paragraph", text: "a" };
    for (let i = 0; i < 8; i++) block = { type: "section", title: "Title", blocks: [block] };
    expect(validateAepPortableDocument({ ...portable, content: [block] }).ok).toBe(true);
    expect(
      validateAepPortableDocument({
        ...portable,
        content: [{ type: "section", title: "Title", blocks: [block] }]
      }).ok
    ).toBe(false);
  });

  it("validates acknowledgement echo and requirement errors", () => {
    expect(
      validateEnrollRequest({ agent_did: "did:web:agent.example", acknowledged_document_ids: [] })
        .ok
    ).toBe(true);
    expect(
      validateEnrollResponse({ status: "active", acknowledged_document_ids: ["Terms.1"] }).ok
    ).toBe(true);
    const problem = {
      type: "urn:aep:error:requirements_unmet",
      title: "Requirements",
      code: "requirements_unmet",
      status: 422,
      requirements_pending: ["contact.email", "service_documents"],
      required_document_ids: ["Terms.1"]
    };
    expect(validateProblemDetails(problem).ok).toBe(true);
    for (const override of [
      { required_document_ids: [] },
      { required_document_ids: undefined },
      { requirements_pending: [] },
      { status: 400 },
      { code: "not_recognized" }
    ])
      expect(validateProblemDetails({ ...problem, ...override }).ok).toBe(false);
  });

  it("requires the extension advertisement with Inspect descriptors", () => {
    const inspect = {
      aep_version: "1.0",
      http: { endpoint_base: "/aep/" },
      bindings: { supported: ["http"] },
      commands: {
        supported: ["inspect", "enroll", "grant", "status", "revoke"],
        grant_types: ["api-key"]
      },
      core: { signing_algorithms: ["ES256", "EdDSA"] },
      service: { did: "did:web:example.com" },
      identity: { methods: ["did:web"] },
      service_documents: [descriptor],
      extensions: { supported: [AEP_SERVICE_DOCUMENTS_EXTENSION] }
    };
    expect(validateInspectDocument(inspect).ok).toBe(true);
    expect(validateInspectDocument({ ...inspect, extensions: { supported: [] } }).ok).toBe(false);
    expect(validateInspectDocument({ ...inspect, service_documents: [] }).ok).toBe(false);
  });
});
