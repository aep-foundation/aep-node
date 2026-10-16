import { createHash, scryptSync } from "node:crypto";

import type { AepBuiltInGrantResponse } from "@aep-foundation/core";
import type { AepStoredServiceCredential } from "../src/index.js";

export function storedCredentialFixture(
  credential: AepBuiltInGrantResponse
): AepStoredServiceCredential {
  const salt = "0123456789abcdef0123456789abcdef";
  const base = {
    credential_id: credential.credential_id,
    expires_at: credential.expires_at,
    scopes: credential.scopes
  };
  if (typeof credential.api_key === "string" && typeof credential.header === "string") {
    return {
      ...base,
      header: credential.header,
      verifier: {
        salt,
        digest: createHash("sha256").update(salt).update(credential.api_key).digest("hex")
      }
    };
  }
  if (typeof credential.access_token === "string") {
    return {
      ...base,
      token_type: "Bearer",
      verifier: {
        salt,
        digest: createHash("sha256").update(salt).update(credential.access_token).digest("hex")
      }
    };
  }
  return {
    ...base,
    username: String(credential.username),
    verifier: {
      salt,
      digest: scryptSync(
        Buffer.from(`${String(credential.username)}:${String(credential.password)}`).toString(
          "base64"
        ),
        salt,
        32
      ).toString("hex")
    }
  };
}
