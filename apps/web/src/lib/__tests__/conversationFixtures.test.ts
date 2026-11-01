import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The redacted run the group-chat e2e suite replays stays redacted.
 *
 * `e2e/conversation-run.json` and `e2e/conversation-evidence.json` were cut
 * from a stored run. Whatever is regenerated into them later must not carry
 * a hash or a piece of one, a real address or host, or the name of a tool,
 * vendor or product: this reads both files and fails on the first of each.
 */

const FIXTURES = ["conversation-run.json", "conversation-evidence.json"].map((name) => ({
  name,
  text: readFileSync(join(__dirname, "../../../e2e", name), "utf8"),
}));

/** Six or more hex characters mixing digits and letters, standing alone — not
 *  inside an identifier and not an `0x` address. */
const HEX_RUN = /(?<![0-9A-Za-z])(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{6,}(?![0-9A-Za-z])/g;
const IPV4 = /(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])/g;
const URL_HOST = /\bhttps?:\/\/([^\s/"'\\<>)\]:]+)/gi;
const BARE_HOST =
  /\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|xyz|top|info|biz|io|cc|pw|site|online|live|club|shop|store|cn|de|uk|us|goog|google)\b/gi;
const DENY = [
  "detect it easy", "jadx", "ilspy", "yara", "unblob", "oletools", "webcrack", "vtai", "r2mcp",
  "upx", "microocer", "updatertag", "bp.dat", "update_data",
  "w32.malware", "ghidra", "radare", "qu1ck", "virustotal", "anthropic", "claude", "haiku",
  "deepseek", "rodectus", "digicert", "goresym", "mozilla", "microsoft", "triage_2",
];

function hits(text: string, pattern: RegExp): string[] {
  return [...text.matchAll(pattern)].map((m) => m[0]);
}

describe.each(FIXTURES)("$name", ({ text }) => {
  it("holds no hash and no piece of one", () => {
    expect(hits(text, HEX_RUN)).toEqual([]);
  });

  it("holds no address outside the documentation range", () => {
    const outside = [...text.matchAll(IPV4)]
      .filter((m) => !(m[1] === "192" && m[2] === "0" && m[3] === "2"))
      .filter((m) => [m[1], m[2], m[3], m[4]].every((octet) => Number(octet) <= 255))
      .map((m) => m[0]);
    expect(outside).toEqual([]);
  });

  it("names no host outside .example", () => {
    const urls = [...text.matchAll(URL_HOST)].map((m) => m[1]).filter((host) => !/\.example$/i.test(host));
    expect(urls).toEqual([]);
    expect(hits(text, BARE_HOST)).toEqual([]);
  });

  it("names no tool, vendor or product", () => {
    const lower = text.toLowerCase();
    expect(DENY.filter((token) => lower.includes(token.toLowerCase()))).toEqual([]);
  });
});
