import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { spilledFileName, spilledProblem } from "../evidenceRows";

const body = new TextEncoder().encode('{"answer": 42}');
const bytes = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
const sha256 = createHash("sha256").update(body).digest("hex");

describe("the file a spilled part is saved as", () => {
  it("carries an extension from the content type", () => {
    expect(spilledFileName("ev_0007", "structured_content", "application/json; charset=utf-8")).toBe(
      "ev_0007-structured_content.json",
    );
    expect(spilledFileName("ev_0007", "output", "text/plain")).toBe("ev_0007-output.txt");
    expect(spilledFileName("ev_0007", "answer", "application/vnd.x+json")).toBe("ev_0007-answer.json");
    expect(spilledFileName("ev_0007", "answer", "")).toBe("ev_0007-answer.bin");
  });
});

const subtle = globalThis.crypto.subtle;
const clean = { problem: null, unverified: null };

describe("whether a fetched spilled part may be saved", () => {
  it("may when its size and digest match the ledger", async () => {
    expect(await spilledProblem(bytes, { bytes: body.byteLength, sha256 }, body.byteLength, subtle)).toEqual(clean);
    expect(await spilledProblem(bytes, {}, null, subtle)).toEqual(clean);
  });

  it("may not when the response was cut short", async () => {
    expect((await spilledProblem(bytes, {}, body.byteLength + 10, subtle)).problem).toMatch(/cut short/);
  });

  it("may not when the size differs from what the ledger kept", async () => {
    expect((await spilledProblem(bytes, { bytes: 9999 }, null, subtle)).problem).toMatch(/ledger kept 9999/);
  });

  it("may not when the digest differs", async () => {
    expect((await spilledProblem(bytes, { sha256: "0".repeat(64) }, null, subtle)).problem).toMatch(/digest/);
  });
});

describe("a spilled part fetched outside a secure context", () => {
  it("is saved with the digest said to be unchecked when crypto.subtle is missing", async () => {
    const check = await spilledProblem(bytes, { bytes: body.byteLength, sha256: "0".repeat(64) }, null, null);
    expect(check.problem).toBeNull();
    expect(check.unverified).toMatch(/digest was not checked .*not a secure context/);
  });

  it("still checks the length when crypto.subtle is missing", async () => {
    const check = await spilledProblem(bytes, { bytes: 9999, sha256 }, null, null);
    expect(check.problem).toMatch(/ledger kept 9999/);
    expect((await spilledProblem(bytes, { sha256 }, body.byteLength + 1, null)).problem).toMatch(/cut short/);
  });
});
