import { SignJWT, importJWK, importPKCS8, importSPKI, importX509, jwtVerify } from "jose";
import type {
  CryptoKey,
  FlattenedJWSInput,
  JWK,
  JWTHeaderParameters,
  JWTVerifyOptions,
  KeyObject
} from "jose";

import { AEP_SIGNING_ALGORITHMS } from "./constants.js";
import { parseClientAssertionClaims } from "./protocol.js";
import type { AepClientAssertionClaims, AepSigningAlgorithm } from "./types.js";

const PROHIBITED_ALGORITHM_PATTERN = /^(?:none|HS[0-9]+|dir|A[0-9]+(?:GCM)?KW|PBES2-.+)$/i;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

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
  allowInsecureLoopback?: boolean;
  key: AepImportableJoseKey;
  kid?: string;
}

export interface VerifyClientAssertionJwtOptions {
  allowInsecureLoopback?: boolean;
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
  assertAgentIdentityAlgorithms([options.alg]);
  const parsed = parseClientAssertionClaims(claims, {
    ...(options.allowInsecureLoopback === undefined
      ? {}
      : { allowInsecureLoopback: options.allowInsecureLoopback })
  });
  const key = await importJoseKey(options.key, options.alg);
  const kid = options.kid ?? parsed.iss;

  requireClientAssertionKid(kid, parsed);

  return new SignJWT(parsed)
    .setProtectedHeader({
      alg: options.alg,
      kid,
      typ: "JWT"
    })
    .sign(key);
}

export async function verifyClientAssertionJwt(
  clientAssertion: string,
  options: VerifyClientAssertionJwtOptions
): Promise<AepClientAssertionClaims> {
  const algorithms = assertAgentIdentityAlgorithms(
    options.algorithms ?? [...AEP_SIGNING_ALGORITHMS]
  );
  const verifyOptions = {
    algorithms,
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
    const key = options.key;
    result = await jwtVerify<AepClientAssertionClaims>(
      clientAssertion,
      (protectedHeader: JWTHeaderParameters) => importJoseKey(key, protectedHeader.alg),
      verifyOptions
    );
  }

  const claims = parseClientAssertionClaims(result.payload, {
    ...(options.allowInsecureLoopback === undefined
      ? {}
      : { allowInsecureLoopback: options.allowInsecureLoopback })
  });

  if (result.protectedHeader.typ !== "JWT" || typeof result.protectedHeader.kid !== "string") {
    throw new Error("Invalid AEP client assertion JOSE header.");
  }

  requireClientAssertionKid(result.protectedHeader.kid, claims);
  return claims;
}

/**
 * Rejects `none` and symmetric JOSE algorithms, which cannot bind an assertion to an Agent
 * identity. Verification defaults to the AEP core signing algorithms rather than to whatever
 * the presented key happens to support, so a token cannot select its own algorithm.
 */
function assertAgentIdentityAlgorithms(algorithms: string[]): string[] {
  if (algorithms.length === 0) {
    throw new TypeError("AEP client assertion verification requires at least one algorithm.");
  }

  for (const algorithm of algorithms) {
    if (PROHIBITED_ALGORITHM_PATTERN.test(algorithm)) {
      throw new TypeError(`AEP Agent identity assertions must not use the ${algorithm} algorithm.`);
    }
  }

  return algorithms;
}

function requireClientAssertionKid(kid: string, claims: AepClientAssertionClaims): void {
  const fragment = kid.indexOf("#");
  const did = fragment === -1 ? kid : kid.slice(0, fragment);

  if (did !== claims.iss || claims.iss !== claims.sub) {
    throw new Error("AEP client assertion kid, iss, and sub must identify the same Agent DID.");
  }
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

/**
 * Decodes the header and payload of a compact JWS without verifying its signature.
 *
 * The token must be exactly three non-empty base64url segments. Callers use this only to
 * discover which key to resolve; the returned claims are untrusted until
 * {@link verifyClientAssertionJwt} has accepted the same token.
 */
export function decodeJwtUnverified(token: string): DecodedJwtParts {
  const segments = token.split(".");
  const [encodedHeader, encodedPayload] = segments;

  if (
    segments.length !== 3 ||
    encodedHeader === undefined ||
    encodedPayload === undefined ||
    !segments.every((segment) => BASE64URL_PATTERN.test(segment))
  ) {
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
