import { describe, expect, it } from "vitest";

import type { EvidenceSection } from "@/types/malware-report";
import {
  RENDERED_TABS,
  binarySectionKeys,
  hasSection,
  importContainerLabel,
  isCoveredBySection,
  sectionHasContent,
  sectionsForTab,
  tabOfSection,
  unrenderedSections,
} from "../reportSections";

function section(over: Partial<EvidenceSection> = {}): EvidenceSection {
  return {
    key: "pe_imports",
    title: "PE imports",
    kind: "table",
    columns: ["Library", "Function", "Category"],
    rows: [["kernel32.dll", "CreateFileW", "file"]],
    text: "",
    items: [],
    evidence_ids: ["ev_0003"],
    source: "tool:pe_info",
    ...over,
  };
}

describe("which tab a section belongs on", () => {
  it("routes the four tables a binary-info tool contributes", () => {
    expect(tabOfSection("pe_header")).toBe("identity");
    expect(tabOfSection("elf_sections")).toBe("static");
    expect(tabOfSection("macho_imports")).toBe("static");
    expect(tabOfSection("apk_exports")).toBe("static");
  });

  it("routes the sections named after what produced them", () => {
    expect(tabOfSection("identity")).toBe("identity");
    expect(tabOfSection("strings")).toBe("static");
    expect(tabOfSection("apk_permissions")).toBe("static");
    expect(tabOfSection("iocs")).toBe("network");
    expect(tabOfSection("sandbox_network")).toBe("network");
    expect(tabOfSection("sandbox_services_and_tasks")).toBe("persistence");
  });

  it("treats anything else the sandbox reported as behaviour", () => {
    expect(tabOfSection("sandbox_processes")).toBe("dynamic");
    expect(tabOfSection("sandbox_mutexes")).toBe("dynamic");
    expect(tabOfSection("sandbox_registry")).toBe("dynamic");
  });

  it("understands a dotted key, so nothing needs renaming twice", () => {
    expect(tabOfSection("static.imports")).toBe("static");
    expect(tabOfSection("persistence.launch_agents")).toBe("persistence");
  });

  it("claims nothing it does not recognise", () => {
    expect(tabOfSection("tool_r2_analysis")).toBe("other");
    expect(tabOfSection("artifact_config")).toBe("other");
    expect(tabOfSection("")).toBe("other");
    expect(tabOfSection("whatever.thing")).toBe("other");
  });

  it("sends the persistence artifact to the persistence tab", () => {
    expect(tabOfSection("artifact_persistence")).toBe("persistence");
  });
});

describe("a section with nothing in it", () => {
  it("is not content", () => {
    expect(sectionHasContent(section({ rows: [] }))).toBe(false);
    expect(sectionHasContent(section({ kind: "text", rows: [], text: "  " }))).toBe(false);
  });

  it("is content when it carries rows, items or prose", () => {
    expect(sectionHasContent(section())).toBe(true);
    expect(sectionHasContent(section({ kind: "list", rows: [], items: ["a"] }))).toBe(true);
    expect(sectionHasContent(section({ kind: "text", rows: [], text: "a" }))).toBe(true);
  });

  it("is left off its tab rather than drawn as an empty table", () => {
    expect(sectionsForTab([section({ rows: [] })], "static")).toEqual([]);
  });
});

describe("the sections one tab draws", () => {
  it("are only its own, in the order they were gathered", () => {
    const sections = [
      section({ key: "identity", kind: "kv" }),
      section({ key: "strings" }),
      section({ key: "pe_imports" }),
      section({ key: "sandbox_network" }),
    ];
    expect(sectionsForTab(sections, "static").map((s) => s.key)).toEqual([
      "strings",
      "pe_imports",
    ]);
  });

  it("are none at all when the report has no sections", () => {
    expect(sectionsForTab(undefined, "static")).toEqual([]);
    expect(sectionsForTab(null, "network")).toEqual([]);
  });
});

describe("whether a typed panel is already covered", () => {
  it("is covered by a section with the same ground and content", () => {
    expect(isCoveredBySection([section()], binarySectionKeys("imports"))).toBe(true);
  });

  it("is not covered by a section that returned nothing", () => {
    expect(isCoveredBySection([section({ rows: [] })], binarySectionKeys("imports"))).toBe(
      false
    );
  });

  it("is not covered by a section about something else", () => {
    expect(isCoveredBySection([section({ key: "strings" })], binarySectionKeys("imports"))).toBe(
      false
    );
  });

  it("names one key at a time when that is all the panel draws", () => {
    expect(hasSection([section({ key: "sandbox_registry" })], "sandbox_registry")).toBe(true);
    expect(hasSection([], "sandbox_registry")).toBe(false);
  });

  it("covers every format the info tools produce", () => {
    expect(binarySectionKeys("sections")).toEqual([
      "pe_sections",
      "elf_sections",
      "macho_sections",
      "apk_sections",
    ]);
  });
});

describe("the imports column header", () => {
  it("follows the format rather than saying Windows in every case", () => {
    expect(importContainerLabel("pe")).toBe("DLL");
    expect(importContainerLabel("elf")).toBe("Shared object");
    expect(importContainerLabel("mach-o")).toBe("Dylib");
    expect(importContainerLabel("apk")).toBe("Package");
  });

  it("stays neutral when the format is unknown", () => {
    expect(importContainerLabel(null)).toBe("Module");
    expect(importContainerLabel("wasm")).toBe("Module");
  });
});


describe("every tab a key can be routed to", () => {
  /* The keys the backend actually emits, from `reporting/ledger_report.py`.
   * Routing one of these to a tab that draws nothing would lose it: it is
   * built, persisted and counted in the evidence metrics, and appears on no
   * page. That is what happened to `identity` and `<prefix>_header`. */
  const BACKEND_KEYS = [
    "identity",
    "pe_header",
    "elf_header",
    "macho_header",
    "apk_header",
    "pe_sections",
    "pe_imports",
    "pe_exports",
    "apk_permissions",
    "apk_components",
    "packer_signatures",
    "strings",
    "yara_matches",
    "sigma_matches",
    "capa_capabilities",
    "functions_examined",
    "iocs",
    "pcap_summary",
    "sandbox_network",
    "sandbox_processes",
    "sandbox_signatures",
    "sandbox_registry",
    "sandbox_api_calls",
    "sandbox_mutexes",
    "sandbox_dropped_files",
    "sandbox_services_and_tasks",
    "artifact_persistence",
    "artifact_config",
    "tool_r2_analysis",
    "findings",
  ];

  it("reaches a page: drawn by its own tab, or caught by the net", () => {
    const netted = new Set(
      unrenderedSections(BACKEND_KEYS.map((key) => section({ key }))).map((s) => s.key)
    );
    for (const key of BACKEND_KEYS) {
      const drawnByItsTab = RENDERED_TABS.has(tabOfSection(key));
      expect(drawnByItsTab || netted.has(key), key).toBe(true);
    }
  });

  it("routes the identity keys to a tab that draws them", () => {
    for (const key of ["identity", "pe_header", "elf_header", "macho_header", "apk_header"]) {
      expect(tabOfSection(key), key).toBe("identity");
      expect(RENDERED_TABS.has("identity")).toBe(true);
    }
  });

  it("names only tabs that exist", () => {
    for (const tab of RENDERED_TABS) expect(tab).not.toBe("other");
  });
});

describe("the net on the evidence tab", () => {
  it("catches a section no tab claims", () => {
    const sections = [section({ key: "tool_r2_analysis" })];
    expect(unrenderedSections(sections).map((s) => s.key)).toEqual(["tool_r2_analysis"]);
  });

  it("leaves a section its own tab draws alone", () => {
    expect(unrenderedSections([section({ key: "pe_imports" })])).toEqual([]);
    expect(unrenderedSections([section({ key: "pe_header", kind: "kv" })])).toEqual([]);
  });

  it("catches every backend key that no tab draws, and only those", () => {
    const sections = [
      section({ key: "identity", kind: "kv" }),
      section({ key: "pe_header", kind: "kv" }),
      section({ key: "findings" }),
      section({ key: "tool_r2_analysis" }),
      section({ key: "artifact_config" }),
    ];
    expect(unrenderedSections(sections).map((s) => s.key)).toEqual([
      "findings",
      "tool_r2_analysis",
      "artifact_config",
    ]);
  });

  it("ignores an empty section, which is a tool that returned nothing", () => {
    expect(unrenderedSections([section({ key: "tool_x", rows: [] })])).toEqual([]);
  });

  it("is nothing at all on a report with no sections", () => {
    expect(unrenderedSections(undefined)).toEqual([]);
  });
});


describe("what the identity tab decides", () => {
  /* The page draws `sectionsForTab(sections, "identity")` above the typed
   * block and stands the typed block down where a header section already
   * carries the same facts. Both halves are pinned here, because the tab that
   * routes these keys drew nothing at all until it did. */
  it("claims the identity block and every format's header table", () => {
    const sections = [
      section({ key: "identity", kind: "kv" }),
      section({ key: "elf_header", kind: "kv" }),
      section({ key: "pe_imports" }),
    ];
    expect(sectionsForTab(sections, "identity").map((s) => s.key)).toEqual([
      "identity",
      "elf_header",
    ]);
  });

  it("stands the typed identity block down when a header section covers it", () => {
    const covered = [section({ key: "macho_header", kind: "kv" })];
    expect(isCoveredBySection(covered, binarySectionKeys("header"))).toBe(true);
  });

  it("keeps the typed identity block when only the identity block was built", () => {
    // `identity` is the routing minimum — format, platform and the hashes the
    // builder computed — not a tool's own header table, so it does not stand
    // in for the report's typed identity.
    const sections = [section({ key: "identity", kind: "kv" })];
    expect(isCoveredBySection(sections, binarySectionKeys("header"))).toBe(false);
  });
});
