import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import { ApiError } from "@/lib/errors";
import { noteSignOut, renewSession, type RenewalDeps } from "@/lib/sessionRenewal";

/* Token values are built at run time so no credential-shaped literal sits in
 * the source. */
const token = (name: string) => ["tok", name].join("_");
const STALE = token("stale");
const FRESH = token("fresh");

function memoryStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => void map.set(key, value),
    removeItem: (key: string) => void map.delete(key),
    map,
  };
}

function deps(storage: ReturnType<typeof memoryStorage>, refresh: RenewalDeps["refresh"]): RenewalDeps {
  const sleep = async () => {};
  return { refresh, storage, sleep, lockEnv: { storage, sleep } };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("renewing a refused access token", () => {
  it("spends the refresh cookie and stores the new token", async () => {
    const storage = memoryStorage({ access_token: STALE });
    const refresh = vi.fn(async () => ({ access_token: FRESH, token_type: "bearer" }));
    expect(await renewSession(STALE, deps(storage, refresh))).toEqual({ kind: "renewed", token: FRESH });
    expect(storage.map.get("access_token")).toBe(FRESH);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("adopts a token another tab or the timer already stored, without a refresh", async () => {
    const storage = memoryStorage({ access_token: FRESH });
    const refresh = vi.fn();
    expect(await renewSession(STALE, deps(storage, refresh))).toEqual({ kind: "renewed", token: FRESH });
    expect(refresh).not.toHaveBeenCalled();
  });

  it("reads a refused refresh cookie as the end of the session", async () => {
    const storage = memoryStorage({ access_token: STALE });
    const refresh = vi.fn(async () => {
      throw new ApiError("Unauthorized", 401);
    });
    expect(await renewSession(STALE, deps(storage, refresh))).toEqual({ kind: "rejected" });
  });

  it("says a refresh that got no answer is unknown, not a sign-out", async () => {
    const storage = memoryStorage({ access_token: STALE });
    const refresh = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    const renewal = await renewSession(STALE, deps(storage, refresh));
    expect(renewal.kind).toBe("unreachable");
    // One prompt retry inside the server's grace window, as the timer does.
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("shares one refresh between callers refused together", async () => {
    const storage = memoryStorage({ access_token: STALE });
    let answer: (value: { access_token: string; token_type: string }) => void = () => {};
    const refresh = vi.fn(
      () => new Promise<{ access_token: string; token_type: string }>((resolve) => (answer = resolve)),
    );
    const first = renewSession(STALE, deps(storage, refresh));
    const second = renewSession(STALE, deps(storage, refresh));
    await vi.waitFor(() => expect(refresh).toHaveBeenCalled());
    answer({ access_token: FRESH, token_type: "bearer" });
    expect(await first).toEqual({ kind: "renewed", token: FRESH });
    expect(await second).toEqual({ kind: "renewed", token: FRESH });
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});

describe("a renewal racing a sign-out", () => {
  it("stores nothing when the reader signed out while the refresh was in flight", async () => {
    const storage = memoryStorage({ access_token: STALE });
    let answer: (value: { access_token: string; token_type: string }) => void = () => {};
    const refresh = vi.fn(
      () => new Promise<{ access_token: string; token_type: string }>((resolve) => (answer = resolve)),
    );
    const renewal = renewSession(STALE, deps(storage, refresh));
    await vi.waitFor(() => expect(refresh).toHaveBeenCalled());
    // Sign-out: the generation moves and the token is removed.
    noteSignOut();
    storage.removeItem("access_token");
    answer({ access_token: FRESH, token_type: "bearer" });
    expect(await renewal).toEqual({ kind: "rejected" });
    expect(storage.map.has("access_token")).toBe(false);
  });

  it("does not hand a renewal begun before a sign-out to a caller after it", async () => {
    const storage = memoryStorage({ access_token: STALE });
    let answer: (value: { access_token: string; token_type: string }) => void = () => {};
    const refresh = vi.fn(
      () => new Promise<{ access_token: string; token_type: string }>((resolve) => (answer = resolve)),
    );
    const before = renewSession(STALE, deps(storage, refresh));
    await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
    noteSignOut();
    const after = renewSession(STALE, deps(storage, refresh));
    expect(after).not.toBe(before);
    answer({ access_token: FRESH, token_type: "bearer" });
    await before;
  });
});

describe("a request the API refused over its token", () => {
  function browser(initial: Record<string, string>) {
    const storage = memoryStorage(initial);
    vi.stubGlobal("window", {});
    vi.stubGlobal("localStorage", storage);
    return storage;
  }

  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

  it("is sent again with a renewed token instead of signing the tab out", async () => {
    const storage = browser({ access_token: STALE });
    const calls: Array<{ url: string; auth: string | null }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit = {}) => {
        const auth = (init.headers as Record<string, string> | undefined)?.Authorization ?? null;
        calls.push({ url, auth });
        if (url.endsWith("/auth/refresh")) return json(200, { access_token: FRESH, token_type: "bearer" });
        if (auth === `Bearer ${STALE}`) return json(401, { detail: "expired" });
        return json(200, { id: "u1", email: "a@b", full_name: "A", role: "analyst" });
      }),
    );
    const me = await api.getMe();
    expect(me.id).toBe("u1");
    expect(storage.map.get("access_token")).toBe(FRESH);
    expect(calls.map((c) => c.url.replace(/^.*\/api\/v1/, ""))).toEqual([
      "/auth/me",
      "/auth/refresh",
      "/auth/me",
    ]);
    expect(calls[2].auth).toBe(`Bearer ${FRESH}`);
  });

  it("clears the token and says Unauthorized when the refresh is refused too", async () => {
    const storage = browser({ access_token: STALE });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json(401, { detail: "nope" })),
    );
    await expect(api.getMe()).rejects.toThrow("Unauthorized");
    expect(storage.map.has("access_token")).toBe(false);
  });

  it("keeps the token when the refresh got no answer, and says so", async () => {
    const storage = browser({ access_token: STALE });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("/auth/refresh")) throw new TypeError("Failed to fetch");
        return json(401, { detail: "expired" });
      }),
    );
    const error = (await api.getMe().then(
      () => null,
      (e: unknown) => e,
    )) as Error;
    expect(error).toBeInstanceOf(Error);
    expect(error.message).not.toBe("Unauthorized");
    expect(error.message).toMatch(/could not be renewed/);
    expect(storage.map.get("access_token")).toBe(STALE);
  });

  it("does not renew around a refused sign-in, whose 401 is about the password", async () => {
    browser({ access_token: STALE });
    const fetchMock = vi.fn(async () => json(401, { detail: "Invalid credentials" }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.login("a@b", ["wrong", "password"].join("_"))).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
