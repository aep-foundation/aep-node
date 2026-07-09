import { SignJWT, importJWK, importPKCS8, importSPKI, importX509, jwtVerify } from "jose";
import type {
  CryptoKey,
  FlattenedJWSInput,
  JWK,
  JWTHeaderParameters,
  JWTVerifyOptions,
  KeyObject
} from "jose";

import { parseClientAssertionClaims } from "./protocol.js";
import type { AepClientAssertionClaims, AepSigningAlgorithm } from "./types.js";

export type AepJoseKey = CryptoKey | JWK | KeyObject | Uint8Array;

export type AepPemKeyFormat = "pkcs8" | "spki" | "x509";

export interface AepPemKey {
  format: AepPemKeyFormat;
  pem: string;
}

export type AepImportableJoseKey = AepJoseKey | AepPemKey;

export type AepJwtVerifyKeyResolver = (
  protectedHeader: JWTHeaderParameters,
  token: FlattenedJWSInput
) => AepImportableJoseKey | Promise<AepImportableJoseKey>;

export interface SignClientAssertionJwtOptions {
  alg: AepSigningAlgorithm;
  key: AepImportableJoseKey;
  kid?: string;
  typ?: string;
}

export interface VerifyClientAssertionJwtOptions {
  algorithms?: AepSigningAlgorithm[];
  audience?: string;
  clockTolerance?: JWTVerifyOptions["clockTolerance"];
  currentDate?: Date;
  issuer?: string;
  key: AepImportableJoseKey | AepJwtVerifyKeyResolver;
  subject?: string;
}

export interface DecodedJwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

export async function signClientAssertionJwt(
  claims: AepClientAssertionClaims,
  options: SignClientAssertionJwtOptions
): Promise<string> {
  const parsed = parseClientAssertionClaims(claims);
  const key = await importJoseKey(options.key, options.alg);

  return new SignJWT(parsed)
    .setProtectedHeader({
      alg: options.alg,
      ...(options.kid === undefined ? {} : { kid: options.kid }),
      typ: options.typ ?? "JWT"
    })
    .sign(key);
}

export async function verifyClientAssertionJwt(
  clientAssertion: string,
  options: VerifyClientAssertionJwtOptions
): Promise<AepClientAssertionClaims> {
  const verifyOptions = {
    ...(options.algorithms === undefined ? {} : { algorithms: options.algorithms }),
    ...(options.audience === undefined ? {} : { audience: options.audience }),
    ...(options.clockTolerance === undefined ? {} : { clockTolerance: options.clockTolerance }),
    ...(options.currentDate === undefined ? {} : { currentDate: options.currentDate }),
    ...(options.issuer === undefined ? {} : { issuer: options.issuer }),
    ...(options.subject === undefined ? {} : { subject: options.subject })
  } satisfies JWTVerifyOptions;
  let result;

  if (typeof options.key === "function") {
    const resolveKey: AepJwtVerifyKeyResolver = options.key;

    result = await jwtVerify<AepClientAssertionClaims>(
      clientAssertion,
      async (protectedHeader: JWTHeaderParameters, token: FlattenedJWSInput) =>
        importJoseKey(await resolveKey(protectedHeader, token), protectedHeader.alg),
      verifyOptions
    );
  } else {
    result = await jwtVerify<AepClientAssertionClaims>(
      clientAssertion,
      await importJoseKey(options.key, options.algorithms?.[0]),
      verifyOptions
    );
  }

  return parseClientAssertionClaims(result.payload);
}

export async function importJoseKey(key: AepImportableJoseKey, alg?: string): Promise<AepJoseKey> {
  if (!isPemKey(key)) {
    return key;
  }

  if (alg === undefined) {
    throw new TypeError("AEP JOSE PEM key import requires an algorithm.");
  }

  if (key.format === "pkcs8") {
    return importPKCS8(key.pem, alg);
  }

  if (key.format === "spki") {
    return importSPKI(key.pem, alg);
  }

  return importX509(key.pem, alg);
}

export async function importJwkJoseKey(jwk: JWK, alg?: string): Promise<AepJoseKey> {
  return importJWK(jwk, alg);
}

export function decodeJwtUnverified(token: string): DecodedJwtParts {
  const [encodedHeader, encodedPayload] = token.split(".");

  if (encodedHeader === undefined || encodedPayload === undefined) {
    throw new Error("Invalid JWT.");
  }

  return {
    header: parseBase64UrlJson(encodedHeader),
    payload: parseBase64UrlJson(encodedPayload)
  };
}

function isPemKey(key: AepImportableJoseKey): key is AepPemKey {
  return typeof key === "object" && "pem" in key && typeof key.pem === "string" && "format" in key;
}

function parseBase64UrlJson(encoded: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));

  if (!isRecord(parsed)) {
    throw new Error("Expected JWT part to decode to an object.");
  }

  return parsed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
