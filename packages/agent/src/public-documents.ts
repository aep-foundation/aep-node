import type { AepAuthenticationMethod, AepOpenApiTrailingSlashMode } from "@aep-foundation/core";

export type AepPublicDocumentNamespace = "inspect" | "platform-discovery" | "openapi";

export interface AepPublicDocumentCacheRecord<T = unknown> {
  namespace: AepPublicDocumentNamespace;
  url: string;
  finalUrl?: string;
  value: T;
  cachedAt: string;
  cacheControl?: string;
  etag?: string;
  lastModified?: string;
}

export interface AepPublicDocumentCache {
  get(
    namespace: AepPublicDocumentNamespace,
    url: string
  ): Promise<AepPublicDocumentCacheRecord | undefined> | AepPublicDocumentCacheRecord | undefined;
  set(record: AepPublicDocumentCacheRecord): Promise<void> | void;
  delete(namespace: AepPublicDocumentNamespace, url: string): Promise<void> | void;
}

export function createInMemoryPublicDocumentCache(
  records: AepPublicDocumentCacheRecord[] = []
): AepPublicDocumentCache {
  const values = new Map(
    records.map((record) => [cacheKey(record.namespace, record.url), structuredClone(record)])
  );
  return {
    delete(namespace, url) {
      values.delete(cacheKey(namespace, url));
    },
    get(namespace, url) {
      const value = values.get(cacheKey(namespace, url));
      return value === undefined ? undefined : structuredClone(value);
    },
    set(record) {
      values.set(cacheKey(record.namespace, record.url), structuredClone(record));
    }
  };
}

export interface FetchAepPublicDocumentOptions<T> {
  namespace: AepPublicDocumentNamespace;
  url: string | URL;
  cache?: AepPublicDocumentCache;
  clock?: () => Date;
  fetch?: (input: URL | string, init?: RequestInit) => Promise<PublicDocumentResponse>;
  maxRedirects?: number;
  maxResponseBytes?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  accept: string;
  acceptedMediaTypes?: string[];
  sameOriginRedirects?: boolean;
  parse(value: unknown): T;
}

export interface AepPublicDocumentResult<T> {
  value: T;
  requestedUrl: URL;
  finalUrl: URL;
  freshness: "fresh" | "revalidated" | "fetched";
  cacheControl?: string;
  etag?: string;
  lastModified?: string;
}

const flights = new WeakMap<
  AepPublicDocumentCache,
  Map<string, Promise<AepPublicDocumentResult<unknown>>>
>();

interface PublicDocumentResponse {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  arrayBuffer?(): Promise<ArrayBuffer>;
  body?: ReadableStream<Uint8Array> | null;
  json(): Promise<unknown>;
  text?(): Promise<string>;
}

export async function fetchAepPublicDocument<T>(
  options: FetchAepPublicDocumentOptions<T>
): Promise<AepPublicDocumentResult<T>> {
  const requestedUrl = safePublicUrl(new URL(options.url));
  const key = cacheKey(options.namespace, String(requestedUrl));
  const cache = options.cache;
  if (cache !== undefined) {
    const map = flights.get(cache) ?? new Map<string, Promise<AepPublicDocumentResult<unknown>>>();
    flights.set(cache, map);
    const existing = map.get(key);
    if (existing !== undefined) return existing as Promise<AepPublicDocumentResult<T>>;
    const flight = fetchDocument(options, requestedUrl).finally(() => map.delete(key));
    map.set(key, flight);
    return flight;
  }
  return fetchDocument(options, requestedUrl);
}

async function fetchDocument<T>(
  options: FetchAepPublicDocumentOptions<T>,
  requestedUrl: URL
): Promise<AepPublicDocumentResult<T>> {
  const now = (options.clock ?? (() => new Date()))();
  const cached = await options.cache?.get(options.namespace, String(requestedUrl));
  if (cached !== undefined && isFresh(cached, now))
    return resultFromRecord(options, requestedUrl, cached, "fresh");
  let current = new URL(cached?.finalUrl ?? requestedUrl);
  const signal = completionSignal(options.signal, options.timeoutMs);
  let response: PublicDocumentResponse;
  for (let redirects = 0; ; redirects += 1) {
    response = await (options.fetch ?? globalThis.fetch)(current, {
      headers: {
        Accept: options.accept,
        ...(cached?.etag === undefined ? {} : { "If-None-Match": cached.etag }),
        ...(cached?.lastModified === undefined ? {} : { "If-Modified-Since": cached.lastModified })
      },
      redirect: "manual",
      signal
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) break;
    if (redirects >= (options.maxRedirects ?? 5))
      throw new TypeError("AEP public document redirect limit exceeded.");
    const location = response.headers.get("location");
    if (location === null) throw new TypeError("AEP public document redirect omitted Location.");
    const next = safePublicUrl(new URL(location, current));
    if (options.sameOriginRedirects === true && next.origin !== current.origin)
      throw new TypeError("AEP public document redirect changed origin.");
    if (current.protocol === "https:" && next.protocol !== "https:")
      throw new TypeError("AEP public document redirect downgraded transport.");
    current = next;
  }
  if (response.status === 304) {
    if (cached === undefined)
      throw new TypeError("AEP public document returned 304 without a cached representation.");
    const record = metadataRecord(
      options.namespace,
      String(current),
      cached.value,
      now,
      response,
      cached
    );
    await persist(options.cache, record, requestedUrl);
    return resultFromRecord(options, requestedUrl, record, "revalidated");
  }
  if (!response.ok) throw new TypeError(`AEP public document failed with HTTP ${response.status}.`);
  if (options.acceptedMediaTypes !== undefined) {
    const mediaType = response.headers.get("content-type");
    if (mediaType === null || !isAcceptedMediaType(mediaType, options.acceptedMediaTypes))
      throw new TypeError("AEP public document response media type is invalid.");
  }
  const bytes = await readBoundedBytes(response, options.maxResponseBytes ?? 1024 * 1024);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new TypeError("AEP public document contains malformed JSON.");
  }
  const value = options.parse(parsed);
  const record = metadataRecord(options.namespace, String(current), value, now, response);
  await persist(options.cache, record, requestedUrl);
  return resultFromRecord(options, requestedUrl, record, "fetched");
}

function metadataRecord<T>(
  namespace: AepPublicDocumentNamespace,
  url: string,
  value: T,
  now: Date,
  response: PublicDocumentResponse,
  prior?: AepPublicDocumentCacheRecord
): AepPublicDocumentCacheRecord<T> {
  const header = (name: string): string | undefined => response.headers.get(name) ?? undefined;
  const cacheControl = header("cache-control") ?? prior?.cacheControl;
  const etag = header("etag") ?? prior?.etag;
  const lastModified = header("last-modified") ?? prior?.lastModified;
  return {
    namespace,
    url,
    value: structuredClone(value),
    cachedAt: now.toISOString(),
    ...(cacheControl === undefined ? {} : { cacheControl }),
    ...(etag === undefined ? {} : { etag }),
    ...(lastModified === undefined ? {} : { lastModified })
  };
}

async function persist(
  cache: AepPublicDocumentCache | undefined,
  record: AepPublicDocumentCacheRecord,
  requestedUrl: URL
): Promise<void> {
  if (cache === undefined) return;
  if (directives(record.cacheControl).has("no-store")) {
    await cache.delete(record.namespace, String(requestedUrl));
    await cache.delete(record.namespace, record.url);
    return;
  }
  await cache.set(record);
  if (record.url !== String(requestedUrl))
    await cache.set({ ...record, url: String(requestedUrl), finalUrl: record.url });
}

function resultFromRecord<T>(
  options: FetchAepPublicDocumentOptions<T>,
  requestedUrl: URL,
  record: AepPublicDocumentCacheRecord,
  freshness: AepPublicDocumentResult<T>["freshness"]
): AepPublicDocumentResult<T> {
  return {
    value: options.parse(structuredClone(record.value)),
    requestedUrl,
    finalUrl: new URL(record.finalUrl ?? record.url),
    freshness,
    ...(record.cacheControl === undefined ? {} : { cacheControl: record.cacheControl }),
    ...(record.etag === undefined ? {} : { etag: record.etag }),
    ...(record.lastModified === undefined ? {} : { lastModified: record.lastModified })
  };
}

function isFresh(record: AepPublicDocumentCacheRecord, now: Date): boolean {
  const control = directives(record.cacheControl);
  if (control.has("no-cache") || control.has("no-store")) return false;
  const maxAge = Number(control.get("max-age") ?? "300");
  const cachedAt = Date.parse(record.cachedAt);
  return (
    Number.isSafeInteger(maxAge) &&
    maxAge >= 0 &&
    !Number.isNaN(cachedAt) &&
    cachedAt + maxAge * 1000 > now.getTime()
  );
}
function directives(value?: string): Map<string, string | undefined> {
  const result = new Map<string, string | undefined>();
  for (const part of value?.split(",") ?? []) {
    const [name, raw] = part.trim().split("=", 2);
    if (name) result.set(name.toLowerCase(), raw?.replace(/^"|"$/g, ""));
  }
  return result;
}
function safePublicUrl(url: URL): URL {
  if (url.username || url.password)
    throw new TypeError("AEP public document URLs must not contain user information.");
  const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
    throw new TypeError("AEP public document URLs require HTTPS except on exact loopback hosts.");
  return url;
}

function completionSignal(signal?: AbortSignal, timeoutMs = 30_000): AbortSignal {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1)
    throw new RangeError("timeoutMs must be a positive integer.");
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
}

async function readBoundedBytes(
  response: PublicDocumentResponse,
  maximum: number
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maximum) || maximum < 1)
    throw new RangeError("maxResponseBytes must be a positive integer.");
  if (response.body === undefined || response.body === null) {
    const bytes =
      response.arrayBuffer === undefined
        ? new TextEncoder().encode(
            response.text === undefined
              ? JSON.stringify(await response.json())
              : await response.text()
          )
        : new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maximum)
      throw new TypeError("AEP public document response is too large.");
    return bytes;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const part = await reader.read();
    if (part.done) break;
    const chunk = part.value;
    size += chunk.byteLength;
    if (size > maximum) {
      await reader.cancel();
      throw new TypeError("AEP public document response is too large.");
    }
    chunks.push(chunk);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
function cacheKey(namespace: AepPublicDocumentNamespace, url: string): string {
  return `${namespace}\u0000${url}`;
}

function isAcceptedMediaType(value: string, accepted: string[]): boolean {
  const actual = parseMediaType(value);
  if (actual === undefined) return false;
  return accepted.some((candidate) => {
    const expected = parseMediaType(candidate);
    if (expected === undefined || expected.type !== actual.type) return false;
    return [...expected.parameters].every(
      ([name, parameter]) => actual.parameters.get(name) === parameter
    );
  });
}

function parseMediaType(
  value: string
): { type: string; parameters: Map<string, string> } | undefined {
  const [rawType, ...rawParameters] = value.split(";");
  const type = rawType?.trim().toLowerCase();
  if (type === undefined || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(type))
    return undefined;
  const parameters = new Map<string, string>();
  for (const rawParameter of rawParameters) {
    const separator = rawParameter.indexOf("=");
    if (separator < 1) return undefined;
    const name = rawParameter.slice(0, separator).trim().toLowerCase();
    const parameter = rawParameter
      .slice(separator + 1)
      .trim()
      .replace(/^"|"$/gu, "")
      .toLowerCase();
    if (name.length === 0 || parameter.length === 0) return undefined;
    parameters.set(name, parameter);
  }
  return { type, parameters };
}

export interface AepOpenApiOperationPolicy {
  source: "openapi";
  matchedOperation?: { method: string; pathTemplate: string };
  state: "public" | "required" | "fallback";
  methods: AepAuthenticationMethod[];
  freshness: AepPublicDocumentResult<unknown>["freshness"];
  strictSlashSuggestion?: string;
}

export function interpretAepOpenApiOperation(
  document: unknown,
  request: { method?: string; url: string | URL; trailingSlash: AepOpenApiTrailingSlashMode },
  freshness: AepOpenApiOperationPolicy["freshness"] = "fetched"
): AepOpenApiOperationPolicy {
  if (
    !isRecord(document) ||
    typeof document["openapi"] !== "string" ||
    !document["openapi"].startsWith("3.1.")
  )
    throw new TypeError("AEP OpenAPI document must use OpenAPI 3.1.");
  const paths = document["paths"];
  if (!isRecord(paths)) return { source: "openapi", state: "fallback", methods: [], freshness };
  const target = new URL(request.url);
  const method = (request.method ?? "GET").toLowerCase();
  const matches = Object.entries(paths).flatMap(([template, item]) =>
    pathMatches(template, target.pathname, request.trailingSlash) &&
    isRecord(item) &&
    isRecord(item[method])
      ? [{ template, operation: item[method], item }]
      : []
  );
  if (matches.length === 0)
    return {
      source: "openapi",
      state: "fallback",
      methods: [],
      freshness,
      ...(request.trailingSlash === "strict"
        ? {
            strictSlashSuggestion: target.pathname.endsWith("/")
              ? target.pathname.slice(0, -1) || "/"
              : `${target.pathname}/`
          }
        : {})
    };
  matches.sort((a, b) => compareTemplateSpecificity(a.template, b.template));
  const match = matches[0];
  const second = matches[1];
  if (match === undefined) return { source: "openapi", state: "fallback", methods: [], freshness };
  if (second !== undefined && compareTemplateSpecificity(match.template, second.template) === 0)
    return { source: "openapi", state: "fallback", methods: [], freshness };
  const security = match.operation["security"] ?? match.item["security"] ?? document["security"];
  const base = {
    source: "openapi" as const,
    matchedOperation: { method: method.toUpperCase(), pathTemplate: match.template },
    freshness
  };
  if (Array.isArray(security) && security.length === 0)
    return { ...base, state: "public", methods: [] };
  if (!Array.isArray(security)) return { ...base, state: "fallback", methods: [] };
  const schemes =
    isRecord(document["components"]) && isRecord(document["components"]["securitySchemes"])
      ? document["components"]["securitySchemes"]
      : {};
  const methods: AepAuthenticationMethod[] = [];
  for (const requirement of security) {
    if (!isRecord(requirement)) continue;
    const names = Object.keys(requirement);
    if (names.length === 0) return { ...base, state: "public", methods: [] };
    if (names.length !== 1) continue;
    const mapped = names.map((name) =>
      isRecord(schemes[name]) ? schemes[name]["x-aep-authentication-method"] : undefined
    );
    if (mapped.every((value): value is AepAuthenticationMethod => typeof value === "string"))
      methods.push(...mapped);
  }
  return methods.length === 0
    ? { ...base, state: "fallback", methods: [] }
    : { ...base, state: "required", methods: [...new Set(methods)] };
}

function pathMatches(template: string, path: string, mode: AepOpenApiTrailingSlashMode): boolean {
  const normalize = (value: string) =>
    mode === "equivalent" && value !== "/" ? value.replace(/\/$/, "") : value;
  const pattern = normalize(template)
    .split("/")
    .map((part) =>
      /^\{[^}]+\}$/.test(part) ? "[^/]+" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    )
    .join("/");
  return new RegExp(`^${pattern}$`).test(normalize(path));
}
function compareTemplateSpecificity(left: string, right: string): number {
  const leftSegments = left.split("/").filter(Boolean);
  const rightSegments = right.split("/").filter(Boolean);
  for (let index = 0; index < Math.max(leftSegments.length, rightSegments.length); index += 1) {
    const leftSegment = leftSegments[index];
    const rightSegment = rightSegments[index];
    const leftLiteral = leftSegment !== undefined && !/^\{[^}]+\}$/.test(leftSegment);
    const rightLiteral = rightSegment !== undefined && !/^\{[^}]+\}$/.test(rightSegment);
    if (leftLiteral !== rightLiteral) return leftLiteral ? -1 : 1;
  }
  return 0;
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
