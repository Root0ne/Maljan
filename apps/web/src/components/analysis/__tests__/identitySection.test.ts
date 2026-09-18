import { describe, expect, it } from "vitest";

import type { EvidenceSection } from "@/types/malware-report";
import { readIdentitySection, signingSentence } from "../identitySection";

/** The `identity` section as `ledger_report._identity` builds it: the routing
 *  facts, then one row per key of `identify_file`, `hashes` and
 *  `signing_info`, with a dict value flattened to `k=v, k=v`. */
function identity(rows: string[][]): EvidenceSection {
  return {
    key: "identity",
    title: "Sample identity",
    kind: "kv",
    columns: ["Field", "Value"],
    rows,
    text: "",
    items: [],
    evidence_ids: ["ev_0001"],
    source: "tool:identify_file",
  };
}

const PE_ROWS = [
  ["file type", "pe"],
  ["platform", "windows"],
  ["md5", "5d41402abc4b2a76b9719d911017c592"],
  ["sha1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"],
  ["sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
  ["authenticode", "present=no, subject=, issuer="],
  ["apk", "present=no, schemes="],
  ["macho", "present=no"],
];

describe("the hashes leave the table", () => {
  it("hands them to the block that draws them, and draws them once", () => {
    const { section, hashes } = readIdentitySection(identity(PE_ROWS), "pe");
    expect(hashes.md5).toBe("5d41402abc4b2a76b9719d911017c592");
    expect(hashes.sha256).toBe(
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    );
    expect(section?.rows.map((r) => r[0])).not.toContain("md5");
    expect(section?.rows.map((r) => r[0])).not.toContain("sha256");
  });

  it("keeps a fingerprint the typed model has no field for", () => {
    const { hashes } = readIdentitySection(
      identity([...PE_ROWS, ["telfhash", "T1A2B3"]]),
      "elf",
    );
    expect(hashes.telfhash).toBe("T1A2B3");
  });

  it("drops a hash the tool reported as nothing", () => {
    const { hashes } = readIdentitySection(identity([["ssdeep", ""]]), "pe");
    expect(hashes.ssdeep).toBeUndefined();
  });
});

describe("the signing rows become the one that applies", () => {
  it("keeps the routed format and drops the formats the sample is not", () => {
    const { section } = readIdentitySection(identity(PE_ROWS), "pe");
    const fields = section?.rows.map((r) => r[0]) ?? [];
    expect(fields).toContain("Authenticode");
    expect(fields).not.toContain("apk");
    expect(fields).not.toContain("macho");
  });

  it("reads what identify_file called the format, not only the routing label", () => {
    // `PE32 executable` is what the tool answers on a report the extractor
    // never rewrote; `pe` is the routing label on one it did.
    const { section } = readIdentitySection(identity(PE_ROWS), "PE32 executable");
    expect(section?.rows.map((r) => r[0])).toContain("Authenticode");
  });

  it("names the routed format for an APK and for a Mach-O", () => {
    const apk = readIdentitySection(
      identity([["apk", "present=yes, schemes=v2, cert_files="]]),
      "apk",
    );
    expect(apk.section?.rows).toEqual([["APK signing", "Carries a signature"]]);

    const macho = readIdentitySection(identity([["macho", "present=no"]]), "mach-o");
    expect(macho.section?.rows).toEqual([["Mach-O signature", "Not signed"]]);
  });

  it("reads present=no as a sentence rather than as prose about a key", () => {
    expect(signingSentence("present=no, subject=, issuer=")).toBe("Not signed");
    expect(signingSentence("present=yes, subject=Acme Ltd")).toBe("Carries a signature");
  });

  it("keeps a signature a format nothing routed still reports", () => {
    // An unknown format: a "no" about a format the sample is not says nothing,
    // but a "yes" is a finding whatever routed.
    const { section } = readIdentitySection(
      identity([
        ["authenticode", "present=no"],
        ["macho", "present=yes"],
      ]),
      "unknown",
    );
    expect(section?.rows).toEqual([["macho signature", "Carries a signature"]]);
  });

  it("draws no row about what the tool looks for", () => {
    /* `format` repeats the routing answer two rows above, and `applicable`
     * says this format has no scheme to look for — which is not a finding
     * about the sample. The export leaves both out; this is the reader's side
     * of the same rule, for a report stored while they were being written. */
    const { section, signing } = readIdentitySection(
      identity([
        ["file type", "elf"],
        ["format", "elf"],
        ["applicable", "no"],
      ]),
      "elf",
    );

    expect(section?.rows).toEqual([["file type", "elf"]]);
    expect(signing).toBe(false);
  });

  it("keeps the signing row for a routed format that has one", () => {
    const { section, signing } = readIdentitySection(
      identity([
        ["file type", "pe"],
        ["format", "pe"],
        ["authenticode", "present=yes, subject=Acme Ltd"],
      ]),
      "pe",
    );

    expect(section?.rows).toEqual([
      ["file type", "pe"],
      ["Authenticode", "Carries a signature"],
    ]);
    expect(signing).toBe(true);
  });

  it("says whether the table states the signing, so the badge can stand down", () => {
    expect(readIdentitySection(identity(PE_ROWS), "pe").signing).toBe(true);
    expect(readIdentitySection(identity([["file type", "pe"]]), "pe").signing).toBe(false);
  });
});

describe("a row that says nothing", () => {
  it("is not drawn", () => {
    const { section } = readIdentitySection(
      identity([
        ["file type", "pe"],
        ["mime type", ""],
        ["language", "-"],
      ]),
      "pe",
    );
    expect(section?.rows).toEqual([["file type", "pe"]]);
  });

  it("leaves no section at all when every row said nothing", () => {
    const { section } = readIdentitySection(identity([["mime type", ""]]), "pe");
    expect(section).toBeNull();
  });

  it("answers for a run with no identity section", () => {
    expect(readIdentitySection(null, "pe")).toEqual({
      section: null,
      hashes: {},
      signing: false,
    });
  });
});
