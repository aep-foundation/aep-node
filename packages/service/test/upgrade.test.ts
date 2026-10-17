import { describe, expect, it } from "vitest";
import {
  createInMemoryServiceCredentialStore,
  migrateServiceCredentialRecord,
  storedApiKeyGrantType,
  storedBasicGrantType,
  storedOAuthBearerGrantType
} from "../src/index.js";
import type { AepLegacyServiceCredentialRecord, AepServiceCredentialStore } from "../src/index.js";

const now = new Date("2026-10-17T00:00:00Z");
const expiry = "2999-01-01T00:00:00Z";
// Shapes captured by issuing each credential with the published Service 0.3.4 package.
const fixtures = [
  {
    grantType: "api-key",
    credential: {
      api_key: "secret-key",
      header: "x-api-key",
      credential_id: "api-key",
      expires_at: expiry,
      scopes: ["read"]
    },
    headers: { "x-api-key": "secret-key" },
    factory: storedApiKeyGrantType
  },
  {
    grantType: "oauth-bearer",
    credential: {
      access_token: "secret-token",
      token_type: "Bearer",
      credential_id: "oauth-bearer",
      expires_at: expiry,
      scopes: ["read"]
    },
    headers: { authorization: "Bearer secret-token" },
    factory: storedOAuthBearerGrantType
  },
  {
    grantType: "basic",
    credential: {
      username: "user",
      password: "secret-password",
      credential_id: "basic",
      expires_at: expiry,
      scopes: ["read"]
    },
    headers: { authorization: `Basic ${Buffer.from("user:secret-password").toString("base64")}` },
    factory: storedBasicGrantType
  }
] as const;

describe("persisted credential upgrades", () => {
  for (const fixture of fixtures) {
    it(`preserves ${fixture.grantType} authentication, revocation and expiry`, async () => {
      const record: AepLegacyServiceCredentialRecord = {
        agentDid: "did:web:agent.example",
        createdAt: now.toISOString(),
        credentialId: fixture.grantType,
        expiresAt: expiry,
        grantType: fixture.grantType,
        credential: { ...fixture.credential, scopes: ["read"] }
      };
      const before = structuredClone(record);
      const converted = await migrateServiceCredentialRecord(record);
      expect(record).toEqual(before);
      expect(converted).toMatchObject({
        agentDid: record.agentDid,
        credentialId: record.credentialId,
        createdAt: record.createdAt,
        expiresAt: expiry,
        credential: { credential_id: fixture.grantType, expires_at: expiry, scopes: ["read"] }
      });
      expect(converted.credential).not.toHaveProperty("api_key");
      expect(converted.credential).not.toHaveProperty("access_token");
      expect(converted.credential).not.toHaveProperty("password");
      expect(await migrateServiceCredentialRecord(converted)).toEqual(converted);
      const extended = await migrateServiceCredentialRecord({
        ...record,
        credential: { ...record.credential, verifier: "issuer-owned extension" }
      });
      expect(extended.credential.verifier).toHaveProperty("digest");

      const store = createInMemoryServiceCredentialStore([converted]);
      const definition = fixture.factory({
        store,
        issue: () => {
          throw new Error("must not reissue");
        }
      });
      const input = { headers: fixture.headers, now };
      await expect(definition.handler?.authenticate?.(input)).resolves.toMatchObject({
        agentDid: record.agentDid,
        credentialId: record.credentialId,
        scopes: ["read"]
      });
      await expect(
        definition.handler?.authenticate?.({
          ...input,
          headers: { authorization: "Bearer wrong", "x-api-key": "wrong" }
        })
      ).resolves.toBeUndefined();
      await expect(
        definition.handler?.authenticate?.({ ...input, now: new Date(expiry) })
      ).resolves.toBeUndefined();
      await store.revokeCredential(
        record.agentDid,
        record.grantType,
        record.credentialId,
        now.toISOString()
      );
      await expect(definition.handler?.authenticate?.(input)).resolves.toBeUndefined();

      // JSON-backed adapters can contain either on-disk format during migration.
      const databaseStore: AepServiceCredentialStore = {
        ...store,
        listCredentials: () => structuredClone([record])
      };
      const reader = fixture.factory({
        store: databaseStore,
        issue: () => {
          throw new Error("must not reissue");
        }
      });
      await expect(reader.handler?.authenticate?.(input)).resolves.toMatchObject({
        credentialId: record.credentialId
      });
      await expect(
        reader.handler?.authenticate?.({ ...input, now: new Date(expiry) })
      ).resolves.toBeUndefined();
      await expect(
        reader.handler?.authenticate?.({
          ...input,
          headers: { authorization: "Bearer wrong", "x-api-key": "wrong" }
        })
      ).resolves.toBeUndefined();
      record.revokedAt = now.toISOString();
      await expect(reader.handler?.authenticate?.(input)).resolves.toBeUndefined();
      const revoked = await migrateServiceCredentialRecord(record);
      expect(revoked.revokedAt).toBe(record.revokedAt);
      record.credentialId = "different";
      await expect(migrateServiceCredentialRecord(record)).rejects.toThrow(
        "credentialId does not match"
      );
    });
  }

  it("rejects an unacknowledged write contract at construction", () => {
    const store = createInMemoryServiceCredentialStore();
    Reflect.deleteProperty(store, "credentialFormat");
    expect(() =>
      storedApiKeyGrantType({
        store,
        issue: () => {
          throw new Error("not issued");
        }
      })
    ).toThrow("credentialFormat");
  });

  it("rejects missing and unrecognized credential bodies with an upgrade error", async () => {
    const record: AepLegacyServiceCredentialRecord = {
      agentDid: "did:web:agent.example",
      createdAt: now.toISOString(),
      credentialId: "api-key",
      expiresAt: expiry,
      grantType: "api-key",
      credential: { ...fixtures[0].credential, scopes: ["read"] }
    };
    Reflect.set(record, "credential", null);
    await expect(migrateServiceCredentialRecord(record)).rejects.toThrow(
      "credential-store upgrade"
    );
    Reflect.set(record, "credential", {});
    await expect(migrateServiceCredentialRecord(record)).rejects.toThrow(
      "credential-store upgrade"
    );
  });
});
