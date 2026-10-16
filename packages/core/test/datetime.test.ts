import { describe, expect, it } from "vitest";

import {
  didWebDocumentUrl,
  validateApiKeyGrantResponse,
  validateBasicGrantResponse,
  validateOAuthBearerGrantResponse
} from "../src/index.js";

function oauthResponse(expiresAt: string): unknown {
  return {
    access_token: "token",
    credential_id: "cred-1",
    expires_at: expiresAt,
    scopes: [],
    token_type: "Bearer"
  };
}

function dateTimeIssue(expiresAt: string): boolean {
  return validateOAuthBearerGrantResponse(oauthResponse(expiresAt)).issues.some(
    (issue) => issue.path === "$.expires_at"
  );
}

describe("RFC 3339 date-time validation", () => {
  it("accepts well-formed instants, including offsets and fractional seconds", () => {
    const accepted = [
      "2026-05-28T12:00:00Z",
      "2026-05-28T12:00:00.123Z",
      "2026-05-28T12:00:00+02:00",
      "2026-05-28T12:00:00.000001-07:00",
      "2024-02-29T00:00:00Z",
      "2000-02-29T00:00:00Z",
      "2026-12-31T23:59:59Z",
      "2026-01-31T00:00:00Z",
      "2026-04-30T00:00:00Z"
    ];

    for (const value of accepted) {
      expect(dateTimeIssue(value)).toBe(false);
    }
  });

  it("rejects a value that does not match the grammar", () => {
    for (const value of ["yesterday", "2026-05-28", "2026-05-28 12:00:00Z", "", "2026-13"]) {
      expect(dateTimeIssue(value)).toBe(true);
    }
  });

  it("rejects an instant the grammar allows but the calendar does not", () => {
    // Month and day bounds.
    expect(dateTimeIssue("2026-00-10T00:00:00Z")).toBe(true);
    expect(dateTimeIssue("2026-13-10T00:00:00Z")).toBe(true);
    expect(dateTimeIssue("2026-05-00T00:00:00Z")).toBe(true);

    // Day past the length of the month, in both a 31-day and a 30-day month.
    expect(dateTimeIssue("2026-01-32T00:00:00Z")).toBe(true);
    expect(dateTimeIssue("2026-04-31T00:00:00Z")).toBe(true);

    // February in a common year, a leap year, and the century rules either way.
    expect(dateTimeIssue("2026-02-29T00:00:00Z")).toBe(true);
    expect(dateTimeIssue("1900-02-29T00:00:00Z")).toBe(true);
    expect(dateTimeIssue("2024-02-30T00:00:00Z")).toBe(true);

    // Grammatically valid, but not a real instant.
    expect(dateTimeIssue("2026-05-28T25:00:00Z")).toBe(true);
  });

  it("applies the same check to API-key and Basic grant responses", () => {
    expect(
      validateApiKeyGrantResponse({
        api_key: "key",
        credential_id: "cred-1",
        expires_at: "2026-02-29T00:00:00Z",
        header: "x-api-key",
        scopes: []
      }).issues.some((issue) => issue.path === "$.expires_at")
    ).toBe(true);

    expect(
      validateBasicGrantResponse({
        credential_id: "cred-1",
        expires_at: "2026-02-29T00:00:00Z",
        password: "pass",
        scopes: [],
        username: "user"
      }).issues.some((issue) => issue.path === "$.expires_at")
    ).toBe(true);
  });

  it("ignores a non-string expiry, which the string check already reports", () => {
    const result = validateOAuthBearerGrantResponse({
      access_token: "token",
      credential_id: "cred-1",
      expires_at: 42,
      scopes: [],
      token_type: "Bearer"
    });

    expect(result.ok).toBe(false);
    expect(result.issues.filter((issue) => issue.message.includes("RFC 3339"))).toHaveLength(0);
  });
});

describe("did:web host normalization", () => {
  it("keeps an IPv6 literal intact and strips its port", () => {
    expect(didWebDocumentUrl("did:web:%5B%3A%3A1%5D%3A8443").toString()).toBe(
      "https://[::1]:8443/.well-known/did.json"
    );
  });

  it("refuses a host that carries user information or resolves to another host", () => {
    for (const did of [
      "did:web:user%40evil.example",
      "did:web:user%3Apass%40evil.example",
      "did:web:evil.example%2Fpath",
      "did:web:%20",
      "did:web:a%2Fb%3Fc"
    ]) {
      expect(() => didWebDocumentUrl(did)).toThrow(/Invalid did:web/u);
    }
  });

  it("downgrades only a loopback host when insecure loopback is allowed", () => {
    expect(
      didWebDocumentUrl("did:web:localhost%3A8080", { allowInsecureLoopback: true }).protocol
    ).toBe("http:");
    expect(
      didWebDocumentUrl("did:web:api.example.com", { allowInsecureLoopback: true }).protocol
    ).toBe("https:");
  });
});
