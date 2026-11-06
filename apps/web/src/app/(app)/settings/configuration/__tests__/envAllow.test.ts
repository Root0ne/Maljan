import { describe, expect, it } from "vitest";
import {
  addedEnvNames,
  requiredEnvNames,
  withRequiredEnvNames,
  type RequiredEnv,
} from "../envAllow";

/* What the API serves on the server-map catalog entry, which is
 * `REQUIRED_ENV_ALLOW` verbatim. The console no longer holds a copy of the
 * names, so what is pinned here is what the editor does with them. */
const SERVED: RequiredEnv = {
  analysis: ["MALSPARK_STAGING_DIR", "MALSPARK_STAGING_TTL_HOURS", "MALSPARK_SAMPLE_ROOTS"],
  network: ["MALSPARK_STAGING_DIR", "MALSPARK_SAMPLE_ROOTS"],
};

describe("the environment names a built-in is always passed", () => {
  it("are whatever the catalog entry named, for the server it named them for", () => {
    expect(requiredEnvNames(SERVED, "analysis")).toContain("MALSPARK_SAMPLE_ROOTS");
    expect(requiredEnvNames(SERVED, "analysis")).toContain("MALSPARK_STAGING_DIR");
    expect(requiredEnvNames(SERVED, "network")).toContain("MALSPARK_SAMPLE_ROOTS");
    expect(requiredEnvNames(SERVED, "network")).toContain("MALSPARK_STAGING_DIR");
  });

  it("are none at all before the schema has been read", () => {
    expect(requiredEnvNames({}, "analysis")).toEqual([]);
    expect(withRequiredEnvNames({}, "analysis", ["MY_OWN_VARIABLE"])).toEqual(["MY_OWN_VARIABLE"]);
  });

  it("holds nothing over threatintel, whose API keys an admin may take away", () => {
    expect(requiredEnvNames(SERVED, "threatintel")).toEqual([]);
    expect(
      addedEnvNames(SERVED, "threatintel", ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]),
    ).toEqual(["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]);
    expect(withRequiredEnvNames(SERVED, "threatintel", [])).toEqual([]);
  });

  it("holds nothing over a server the operator added", () => {
    expect(requiredEnvNames(SERVED, "r2custom")).toEqual([]);
    expect(withRequiredEnvNames(SERVED, "r2custom", ["R2_HOME"])).toEqual(["R2_HOME"]);
    expect(addedEnvNames(SERVED, "r2custom", ["MALSPARK_SAMPLE_ROOTS"])).toEqual([
      "MALSPARK_SAMPLE_ROOTS",
    ]);
  });
});

describe("the editable part of a built-in's list", () => {
  it("is what is left once the fixed names are out", () => {
    expect(
      addedEnvNames(SERVED, "analysis", [
        "MALSPARK_STAGING_DIR",
        "MALSPARK_STAGING_TTL_HOURS",
        "MALSPARK_SAMPLE_ROOTS",
        "MY_OWN_VARIABLE",
      ]),
    ).toEqual(["MY_OWN_VARIABLE"]);
  });

  it("is staged back under the fixed names, in the order the API stores them", () => {
    expect(withRequiredEnvNames(SERVED, "analysis", ["MY_OWN_VARIABLE"])).toEqual([
      "MALSPARK_STAGING_DIR",
      "MALSPARK_STAGING_TTL_HOURS",
      "MALSPARK_SAMPLE_ROOTS",
      "MY_OWN_VARIABLE",
    ]);
  });

  it("keeps a fixed name once when it is typed into the box as well", () => {
    expect(
      withRequiredEnvNames(SERVED, "network", ["MALSPARK_SAMPLE_ROOTS", "MY_OWN_VARIABLE"]),
    ).toEqual(["MALSPARK_STAGING_DIR", "MALSPARK_SAMPLE_ROOTS", "MY_OWN_VARIABLE"]);
  });

  it("cannot be emptied of the fixed names, which is what the box is for", () => {
    expect(withRequiredEnvNames(SERVED, "network", [])).toEqual([
      "MALSPARK_STAGING_DIR",
      "MALSPARK_SAMPLE_ROOTS",
    ]);
  });
});
