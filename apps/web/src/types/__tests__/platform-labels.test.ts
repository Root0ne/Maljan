import { describe, expect, it } from "vitest";

import { FILE_TYPE_LABELS, PLATFORM_LABELS, fileTypeLabel, platformLabel } from "../malware-report";

describe("platformLabel", () => {
  it("names every platform the backend emits", () => {
    expect(Object.keys(PLATFORM_LABELS).sort()).toEqual([
      "android",
      "ios",
      "linux",
      "macos",
      "multi",
      "unknown",
      "windows",
    ]);
    expect(platformLabel("macos")).toBe("macOS");
    expect(platformLabel("multi")).toBe("Cross-platform");
  });

  it("renders a platform it has no label for as itself", () => {
    // The backend type is a plain string: no sample is refused for its
    // platform, so an unlisted value must render rather than disappear.
    expect(platformLabel("solaris")).toBe("solaris");
  });

  it("falls back to Unknown for an absent platform", () => {
    expect(platformLabel(null)).toBe("Unknown");
    expect(platformLabel(undefined)).toBe("Unknown");
    expect(platformLabel("")).toBe("Unknown");
  });
});

describe("fileTypeLabel", () => {
  it("names the lowercase routing labels the backend emits", () => {
    expect(fileTypeLabel("pe")).toBe("PE");
    expect(fileTypeLabel("elf")).toBe("ELF");
    expect(fileTypeLabel("mach-o")).toBe("Mach-O");
    expect(fileTypeLabel("ooxml")).toBe("OOXML");
    expect(FILE_TYPE_LABELS["7z"]).toBe("7-Zip");
  });

  it("renders a type it has no label for as itself", () => {
    expect(fileTypeLabel("nonsense")).toBe("nonsense");
  });

  it("falls back to Unknown for an absent type", () => {
    expect(fileTypeLabel(null)).toBe("Unknown");
    expect(fileTypeLabel("")).toBe("Unknown");
  });
});
