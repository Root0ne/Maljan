import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  configureRunCredentials,
  configureRunTransport,
  getRun,
  refusalKind,
  resetRun,
  subscribeRun,
  type RunSocketHandlers,
} from "@/lib/runStore";

/**
 * The live feed when the server closes it over its credential.
 *
 * The server closes with 1008 for an expired token and for a job that is not
 * the reader's, and says which in the reason. A token that expired an hour
 * into a run used to end the feed with "sign in again" for a reader who was
 * still signed in.
 */

const JOB = "job-renew";
const token = (name: string) => ["tok", name].join("_");

interface Dial {
  token: string | null;
  handlers: RunSocketHandlers;
}

function setup(renew: (refused: string | null) => Promise<string | null>) {
  let held: string | null = token("first");
  const dials: Dial[] = [];
  const renewals: Array<string | null> = [];
  configureRunCredentials({
    current: () => held,
    renew: async (refused) => {
      renewals.push(refused);
      const next = await renew(refused);
      if (next) held = next;
      return next;
    },
  });
  configureRunTransport({
    async readEvents() {
      return [];
    },
    connect(_jobId, _since, handlers) {
      dials.push({ token: held, handlers });
      return { close() {} };
    },
  });
  return {
    dials,
    renewals,
    setHeld: (value: string | null) => {
      held = value;
    },
  };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  resetRun(JOB);
  configureRunTransport(null);
  configureRunCredentials(null);
  vi.useRealTimers();
});

describe("why the server refused a socket", () => {
  it("reads an unauthorised close as the credential", () => {
    expect(refusalKind(1008, "Unauthorized: invalid token")).toBe("credential");
    expect(refusalKind(1008, "Unauthorized: account is deactivated or the session was revoked")).toBe(
      "credential",
    );
    expect(refusalKind(4401, "anything")).toBe("credential");
    expect(refusalKind(1008, "")).toBe("credential");
  });

  it("reads a refusal over the request as one no token changes", () => {
    expect(refusalKind(1008, "Not found: job does not exist")).toBe("request");
    expect(refusalKind(1008, "Forbidden: not your job")).toBe("request");
    expect(refusalKind(1008, "Bad request: invalid job ID")).toBe("request");
  });

  it("is no refusal at all for a dropped connection", () => {
    expect(refusalKind(1006, "")).toBeNull();
    expect(refusalKind(1000, "bye")).toBeNull();
  });
});

/* What the server does with a token it refuses: it accepts the socket, then
 * checks the credential and closes with 1008. `open` precedes every refusal. */
function refuse(dial: Dial, reason = "Unauthorized: invalid token") {
  dial.handlers.onOpen();
  dial.handlers.onClose(1008, reason);
}

describe("a feed closed over its credential", () => {
  it("renews the token and dials again, backed off, with the new one", async () => {
    const { dials, renewals } = setup(async () => token("second"));
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    refuse(dials[0]);
    await vi.advanceTimersByTimeAsync(0);
    expect(renewals).toEqual([token("first")]);
    await vi.advanceTimersByTimeAsync(31_000);

    expect(dials).toHaveLength(2);
    expect(dials[1].token).toBe(token("second"));
    expect(getRun(JOB).connection).not.toBe("unauthorized");
  });

  it("renews once per refusal chain however often the server opens and refuses", async () => {
    let n = 0;
    const { dials, renewals } = setup(async () => token(`r${(n += 1)}`));
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    for (let i = 0; i < 5 && dials[i]; i++) {
      refuse(dials[i]);
      await vi.advanceTimersByTimeAsync(60_000);
    }

    expect(renewals).toHaveLength(1);
    expect(dials).toHaveLength(2);
    expect(getRun(JOB).connection).toBe("unauthorized");
  });

  it("may renew again once a socket has carried a frame", async () => {
    let n = 0;
    const { dials, renewals } = setup(async () => token(`r${(n += 1)}`));
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    refuse(dials[0]);
    await vi.advanceTimersByTimeAsync(31_000);
    dials[1].handlers.onOpen();
    dials[1].handlers.onAlive?.();
    // An hour later the renewed token expires too.
    dials[1].handlers.onClose(1008, "Unauthorized: invalid token");
    await vi.advanceTimersByTimeAsync(31_000);

    expect(renewals).toHaveLength(2);
    expect(dials).toHaveLength(3);
  });

  it("may renew again once a socket has stayed open for a stable interval", async () => {
    let n = 0;
    const { dials, renewals } = setup(async () => token(`r${(n += 1)}`));
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    refuse(dials[0]);
    await vi.advanceTimersByTimeAsync(31_000);
    dials[1].handlers.onOpen();
    await vi.advanceTimersByTimeAsync(10_000);
    dials[1].handlers.onClose(1008, "Unauthorized: invalid token");
    await vi.advanceTimersByTimeAsync(31_000);

    expect(renewals).toHaveLength(2);
  });

  it("does not dial for nobody when the last reader leaves during the backoff", async () => {
    const { dials, renewals } = setup(async () => token("second"));
    const leave = subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    refuse(dials[0]);
    await vi.advanceTimersByTimeAsync(0);
    expect(renewals).toHaveLength(1);
    // The redial is scheduled while the reader is still here; it leaves
    // before the backoff (at most a second on a first attempt) runs out.
    leave();
    await vi.advanceTimersByTimeAsync(2_000);

    expect(dials).toHaveLength(1);
    expect(getRun(JOB).connection).toBe("closed");
  });

  it("uses a newer token already held without a renewal", async () => {
    const { dials, renewals, setHeld } = setup(async () => null);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);
    setHeld(token("timer"));

    refuse(dials[0]);
    await vi.advanceTimersByTimeAsync(31_000);

    expect(renewals).toEqual([]);
    expect(dials).toHaveLength(2);
    expect(dials[1].token).toBe(token("timer"));
  });

  it("asks the reader to sign in only when no token can be had", async () => {
    const { dials } = setup(async () => null);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    refuse(dials[0]);
    await vi.advanceTimersByTimeAsync(60_000);

    expect(dials).toHaveLength(1);
    expect(getRun(JOB).connection).toBe("unauthorized");
  });

  it("is refused for good, without a renewal, over a job that is not the reader's", async () => {
    const { dials, renewals } = setup(async () => token("second"));
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    refuse(dials[0], "Forbidden: not your job");
    await vi.advanceTimersByTimeAsync(60_000);

    expect(renewals).toEqual([]);
    expect(dials).toHaveLength(1);
    expect(getRun(JOB).connection).toBe("refused");
  });
});
