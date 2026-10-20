import { describe, expect, it } from "vitest";

import type { MalwareReport } from "@/types/malware-report";
import {
  claimsNotDiscussed,
  flaggedMark,
  flaggedStatements,
  hasTechnicalAnalysis,
  technicalSubsections,
} from "../reportProse";

const report = (over: Partial<MalwareReport>) => over as MalwareReport;

describe("the rest of the technical-analysis spine", () => {
  it("draws each subsection that says something, and none that is empty", () => {
    const mr = report({
      technical_analysis: {
        packing_obfuscation: { title: "Packing", body: "Packed, unpacked in memory.", evidence_refs: ["ev_0002"] },
        discovery: { title: "Discovery", body: "" },
        cli_flags: [{ flag: "-path", description: "folder to encrypt" }],
        shadow_copy_destruction: ["vssadmin delete shadows /all /quiet"],
        encryption_scheme: { cipher: "AES-256", mode: "CBC", per_file_key: true, evidence_ref: "ev_0009" },
        service_process_kill: { kill_list: ["sql.exe"], white_list: [], mechanism: null },
        ransom_note: { filename: "README.txt", verbatim_content: "Your files are encrypted", sections: [] },
      },
    });
    const blocks = technicalSubsections(mr);
    expect(blocks.map((b) => b.key)).toEqual([
      "packing_obfuscation",
      "cli_flags",
      "service_process_kill",
      "shadow_copy_destruction",
      "encryption_scheme",
      "ransom_note",
    ]);
    expect(blocks[0]).toMatchObject({ title: "Packing", evidence: ["ev_0002"] });
    expect(blocks[1].items).toEqual(["-path — folder to encrypt"]);
    expect(blocks[2].facts).toEqual([["Stops", "sql.exe"]]);
    expect(blocks[4].facts).toEqual([
      ["Cipher", "AES-256"],
      ["Mode", "CBC"],
      ["Per-file key", "yes"],
    ]);
    expect(blocks[5]).toMatchObject({ body: "Your files are encrypted", facts: [["File name", "README.txt"]] });
    expect(hasTechnicalAnalysis(mr)).toBe(true);
  });

  it("leaves a per-file key the model did not establish out rather than saying no", () => {
    const mr = report({ technical_analysis: { encryption_scheme: { cipher: "ChaCha20", per_file_key: null } } });
    expect(technicalSubsections(mr)[0].facts).toEqual([["Cipher", "ChaCha20"]]);
  });

  it("draws nothing for a report with no spine", () => {
    expect(technicalSubsections(report({}))).toEqual([]);
    expect(technicalSubsections(report({ technical_analysis: { encryption_scheme: {} } }))).toEqual([]);
  });
});

describe("what the report's own checks left standing", () => {
  it("lists flagged sentences with whether the model was asked", () => {
    const mr = report({
      flagged_statements: [
        { sentence: "It steals credentials.", code: "capability_unsupported", label: "credential theft" },
        { sentence: "It maps T1003.", code: "rule_only", asked: false },
        { sentence: "   ", code: "x" },
      ],
    });
    const flagged = flaggedStatements(mr);
    expect(flagged).toHaveLength(2);
    expect(flaggedMark(flagged[0])).toBe("credential theft — asked about and left standing");
    expect(flaggedMark(flagged[1])).toBe("rule_only — the model was not asked about it");
  });

  it("lists the claims the body does not discuss", () => {
    const mr = report({
      claims_not_discussed: [{ agent: "static", claim_number: 3, claim: "Imports CryptEncrypt", missing: ["CryptEncrypt"] }],
    });
    expect(claimsNotDiscussed(mr)).toHaveLength(1);
    expect(claimsNotDiscussed(report({}))).toEqual([]);
  });
});
