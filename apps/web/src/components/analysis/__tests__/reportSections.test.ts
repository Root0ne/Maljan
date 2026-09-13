import { describe, expect, it } from "vitest";

import type { EvidenceSection } from "@/types/malware-report";
import {
  binarySectionKeys,
  hasSection,
  importContainerLabel,
  isCoveredBySection,
  sectionHasContent,
  sectionsForTab,
  tabOfSection,
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
