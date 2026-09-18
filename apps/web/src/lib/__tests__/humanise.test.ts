import { describe, expect, it } from "vitest";
import { humaniseKey, humaniseRow, humaniseValue } from "../humanise";

describe("a machine key as a heading", () => {
  it("reads a snake_case key as a sentence", () => {
    expect(humaniseKey("optional_dependency")).toBe("Optional dependency");
    expect(humaniseKey("malware_category")).toBe("Malware category");
    expect(humaniseKey("sample_count")).toBe("Sample count");
  });

  it("leaves an acronym as letters wherever it falls", () => {
    expect(humaniseKey("ioc")).toBe("IOC");
    expect(humaniseKey("ioc_count")).toBe("IOC count");
    expect(humaniseKey("technique_ids")).toBe("Technique IDs");
    expect(humaniseKey("sha256")).toBe("SHA256");
    expect(humaniseKey("source_ip")).toBe("Source IP");
  });

  it("reads a dotted key too, and an empty one as nothing", () => {
    expect(humaniseKey("capabilities.tools")).toBe("Capabilities tools");
    expect(humaniseKey("")).toBe("");
  });
});

describe("a header value as an analyst quotes it", () => {
  it("names the PE constants", () => {
    expect(humaniseValue("machine", "34404")).toBe("x86-64");
    expect(humaniseValue("subsystem", "2")).toBe("Windows GUI");
  });

  it("leaves a constant nothing here lists as the number it was", () => {
    expect(humaniseValue("machine", "9999")).toBe("9999");
  });

  it("reads a byte count, an epoch and an entry point", () => {
    expect(humaniseValue("size", "4486656")).toBe("4.28 MB");
    expect(humaniseValue("timestamp", "1566949827")).toBe("2019-08-27 23:50:27 UTC");
    expect(humaniseValue("entry point", "321264")).toBe("0x0004e6f0");
  });

  it("says an unstamped PE is unstamped rather than dating it to 1970", () => {
    expect(humaniseValue("timestamp", "0")).toBe("not stamped");
  });

  it("writes the routed format the way the format is written", () => {
    expect(humaniseValue("file_type", "pe")).toBe("PE");
    expect(humaniseValue("file_type", "mach-o")).toBe("Mach-O");
  });

  it("leaves a value it has no rule for alone", () => {
    expect(humaniseValue("signer_subject", "Simon Tatham")).toBe("Simon Tatham");
    expect(humaniseValue("size", "not a number")).toBe("not a number");
  });
});

describe("a whole key/value row", () => {
  it("reads both halves", () => {
    expect(humaniseRow(["file_type", "pe"])).toEqual(["File type", "PE"]);
    expect(humaniseRow(["entry_point", "321264"])).toEqual(["Entry point", "0x0004e6f0"]);
  });
});
