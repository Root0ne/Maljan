import { describe, expect, it } from "vitest";
import {
  REQUIRED_ENV_ALLOW,
  addedEnvNames,
  requiredEnvNames,
  withRequiredEnvNames,
} from "../envAllow";

describe("the environment names a built-in is always passed", () => {
  it("names the sample roots and the staging directory on both file-reading sidecars", () => {
    expect(requiredEnvNames("analysis")).toContain("MALJAN_SAMPLE_ROOTS");
    expect(requiredEnvNames("analysis")).toContain("MALJAN_STAGING_DIR");
    expect(requiredEnvNames("network")).toContain("MALJAN_SAMPLE_ROOTS");
    expect(requiredEnvNames("network")).toContain("MALJAN_STAGING_DIR");
  });

  it("names nothing that is a credential, on any server", () => {
    const named = Object.values(REQUIRED_ENV_ALLOW).flatMap((names) => [...names]);
    expect(new Set(named)).toEqual(
      new Set(["MALJAN_SAMPLE_ROOTS", "MALJAN_STAGING_DIR", "MALJAN_STAGING_TTL_HOURS"]),
    );
  });

  it("holds nothing over threatintel, whose API keys an admin may take away", () => {
    expect(requiredEnvNames("threatintel")).toEqual([]);
    expect(addedEnvNames("threatintel", ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"])).toEqual([
      "VIRUSTOTAL_API_KEY",
      "ABUSEIPDB_API_KEY",
    ]);
    expect(withRequiredEnvNames("threatintel", [])).toEqual([]);
  });

  it("holds nothing over a server the operator added", () => {
    expect(requiredEnvNames("r2custom")).toEqual([]);
    expect(withRequiredEnvNames("r2custom", ["R2_HOME"])).toEqual(["R2_HOME"]);
    expect(addedEnvNames("r2custom", ["MALJAN_SAMPLE_ROOTS"])).toEqual(["MALJAN_SAMPLE_ROOTS"]);
  });
});

describe("the editable part of a built-in's list", () => {
  it("is what is left once the fixed names are out", () => {
    expect(
      addedEnvNames("analysis", [
        "MALJAN_STAGING_DIR",
        "MALJAN_STAGING_TTL_HOURS",
        "MALJAN_SAMPLE_ROOTS",
        "MY_OWN_VARIABLE",
      ]),
    ).toEqual(["MY_OWN_VARIABLE"]);
  });

  it("is staged back under the fixed names, in the order the API stores them", () => {
    expect(withRequiredEnvNames("analysis", ["MY_OWN_VARIABLE"])).toEqual([
      "MALJAN_STAGING_DIR",
      "MALJAN_STAGING_TTL_HOURS",
      "MALJAN_SAMPLE_ROOTS",
      "MY_OWN_VARIABLE",
    ]);
  });

  it("keeps a fixed name once when it is typed into the box as well", () => {
    expect(withRequiredEnvNames("network", ["MALJAN_SAMPLE_ROOTS", "MY_OWN_VARIABLE"])).toEqual([
      "MALJAN_STAGING_DIR",
      "MALJAN_SAMPLE_ROOTS",
      "MY_OWN_VARIABLE",
    ]);
  });

  it("cannot be emptied of the fixed names, which is what the box is for", () => {
    expect(withRequiredEnvNames("network", [])).toEqual([
      "MALJAN_STAGING_DIR",
      "MALJAN_SAMPLE_ROOTS",
    ]);
  });
});
