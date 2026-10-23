import { afterEach, describe, expect, it } from "vitest";
import { refreshAccessToken } from "@/lib/refreshRequest";

class MemoryStorage {
  values = new Map<string, string>();
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
}

const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");

afterEach(() => {
  if (original) Object.defineProperty(globalThis, "localStorage", original);
  else delete (globalThis as { localStorage?: unknown }).localStorage;
});

function respond(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })) as typeof fetch;
}

describe("refreshAccessToken", () => {
  it("leaves the stored token alone on a 401", async () => {
    const storage = new MemoryStorage();
    storage.setItem("access_token", "the-winning-tabs-token");
    Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true });

    await expect(
      refreshAccessToken("http://api", respond(401, { detail: "rotated" })),
    ).rejects.toMatchObject({ message: "Unauthorized", status: 401 });

    expect(storage.getItem("access_token")).toBe("the-winning-tabs-token");
  });

  it("returns the new token and passes the abort signal through", async () => {
    let seen: AbortSignal | undefined;
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      seen = init?.signal ?? undefined;
      return new Response(JSON.stringify({ access_token: "new", token_type: "bearer" }), {
        status: 200,
      });
    }) as typeof fetch;
    const controller = new AbortController();

    const token = await refreshAccessToken("http://api", fetchImpl, controller.signal);

    expect(token.access_token).toBe("new");
    expect(seen).toBe(controller.signal);
  });

  it("names any other failure", async () => {
    await expect(
      refreshAccessToken("http://api", respond(503, { detail: "down" })),
    ).rejects.toMatchObject({ message: "down", status: 503 });
  });
});
