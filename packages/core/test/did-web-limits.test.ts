import { describe, expect, it, vi } from "vitest";
import { resolveDidWebPublicKey } from "../src/index.js";

const did = "did:web:agent.example";
const document = JSON.stringify({
  id: did,
  verificationMethod: [{ id: did, publicKeyJwk: { kty: "OKP" } }],
  description: "é"
});
const bytes = new TextEncoder().encode(document);

describe("DID document response limits", () => {
  it("accepts the exact byte limit and preserves split UTF-8 characters", async () => {
    let offset = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset === bytes.length) controller.close();
        else controller.enqueue(bytes.slice(offset, ++offset));
      }
    });
    await expect(
      resolveDidWebPublicKey({
        did,
        kid: did,
        maxBytes: bytes.length,
        fetch: () => Promise.resolve(new Response(body))
      })
    ).resolves.toEqual({ kty: "OKP" });
  });

  it("counts bytes rather than UTF-16 characters", async () => {
    await expect(
      resolveDidWebPublicKey({
        did,
        kid: did,
        maxBytes: document.length,
        fetch: () => Promise.resolve(new Response(document))
      })
    ).rejects.toThrow("exceeded");
  });

  it("cancels an oversized stream without reading the remainder", async () => {
    const cancel = vi.fn();
    const pull = vi.fn((controller: ReadableStreamDefaultController<Uint8Array>) => {
      controller.enqueue(new Uint8Array(9));
    });
    const body = new ReadableStream<Uint8Array>({ pull, cancel }, { highWaterMark: 0 });
    await expect(
      resolveDidWebPublicKey({
        did,
        kid: did,
        maxBytes: 8,
        fetch: () => Promise.resolve(new Response(body))
      })
    ).rejects.toThrow("exceeded 8 bytes");
    expect(pull).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(body.locked).toBe(false);
  });

  it.each([0, -1, 1.5, Infinity, NaN])(
    "rejects an invalid bound %s before fetching",
    async (maxBytes) => {
      const fetch = vi.fn(() => Promise.resolve(new Response(document)));
      await expect(resolveDidWebPublicKey({ did, kid: did, maxBytes, fetch })).rejects.toThrow(
        "maxBytes"
      );
      expect(fetch).not.toHaveBeenCalled();
    }
  );

  it("rejects an empty response", async () => {
    await expect(
      resolveDidWebPublicKey({
        did,
        kid: did,
        fetch: () => Promise.resolve(new Response(null))
      })
    ).rejects.toThrow("not valid JSON");
  });

  it("releases the reader when the response stream fails", async () => {
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error("connection lost"));
      }
    });
    await expect(
      resolveDidWebPublicKey({
        did,
        kid: did,
        fetch: () => Promise.resolve(new Response(body))
      })
    ).rejects.toThrow("connection lost");
    expect(body.locked).toBe(false);
  });
});
